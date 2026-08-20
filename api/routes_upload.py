from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock
from typing import Any, Deque, Dict, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse

import db
from auth_apikey import get_api_client, require_permission
from config import settings
from encryption_detect import detect_mime_type

logger = logging.getLogger("scanner.upload")

router = APIRouter(prefix="/api/v1", tags=["Universal Upload API"])

# Separate, more restrictive rate limiter for uploads specifically (vs
# general API requests) - keyed by API client id. Mirrors api/main.py's
# RateLimiter but reads its limit from system_settings so an admin can
# tune it without a redeploy.
_upload_hits: Dict[str, Deque[float]] = defaultdict(deque)
_upload_hits_lock = Lock()


def _upload_rate_limit_ok(client_id: str) -> bool:
    limit = int(db.get_system_settings().get("rate_limit_uploads_per_minute", 30))
    now = time.monotonic()
    window_start = now - 60.0
    with _upload_hits_lock:
        q = _upload_hits[client_id]
        while q and q[0] < window_start:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True


def _error(status_code: int, message: str, **extra: Any) -> JSONResponse:
    body = {"status": "ERROR", "allowed": False, "message": message}
    body.update(extra)
    return JSONResponse(status_code=status_code, content=body)


class UploadTooLarge(Exception):
    pass


class UploadEmpty(Exception):
    pass


async def stream_upload_to_staging(file: UploadFile, max_size: int, request_id: str) -> Dict[str, Any]:
    """
    Streams `file` to a temp dir under STAGING_BASE, hashing (sha256 +
    md5) as it goes and enforcing `max_size` mid-stream rather than after
    the fact. Shared by the API-key-authenticated universal upload
    endpoint below AND the panel's session-authenticated manual upload
    page (panel/upload.py) - both need identical staging/hashing/size-limit
    behavior, just different auth and different scan-row metadata.

    Raises UploadTooLarge / UploadEmpty on policy violations (caller
    decides the HTTP status/response shape for its own context); the temp
    dir is always cleaned up before raising. On success, the temp dir is
    NOT cleaned up yet - the caller must move `tmp_path` into its final
    STAGING_BASE/<scan_id>/input/ location and then remove `tmp_dir`.
    """
    tmp_dir = Path(settings.staging_base) / f"upload-tmp-{request_id}"
    tmp_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    original_filename = file.filename or "upload.bin"
    tmp_path = tmp_dir / "upload.bin"

    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    total_size = 0
    try:
        with open(tmp_path, "wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total_size += len(chunk)
                if total_size > max_size:
                    _rmtree_quiet(tmp_dir)
                    raise UploadTooLarge()
                sha256.update(chunk)
                md5.update(chunk)
                out.write(chunk)
    finally:
        await file.close()

    if total_size == 0:
        _rmtree_quiet(tmp_dir)
        raise UploadEmpty()

    return {
        "tmp_dir": tmp_dir,
        "tmp_path": tmp_path,
        "original_filename": original_filename,
        "sha256_hex": sha256.hexdigest(),
        "md5_hex": md5.hexdigest(),
        "total_size": total_size,
    }


def finalize_staged_upload(scan_id: str, staged: Dict[str, Any]) -> None:
    """Moves a `stream_upload_to_staging` result into its permanent
    STAGING_BASE/<scan_id>/input/<filename> location (where
    ansible/scan_uploaded_file.yml expects to find it) and cleans up the
    temp dir. Shared by both upload entry points."""
    final_input_dir = Path(settings.staging_base) / scan_id / "input"
    final_input_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    final_path = final_input_dir / staged["original_filename"]
    staged["tmp_path"].replace(final_path)
    _rmtree_quiet(staged["tmp_dir"])
    db.update_scan(scan_id, staging_path=str(Path(settings.staging_base) / scan_id))


@router.post("/files/upload", status_code=status.HTTP_202_ACCEPTED)
async def upload_file(
    request: Request,
    file: UploadFile,
    username: str = Form(...),
    user_id: Optional[str] = Form(None),
    email: Optional[str] = Form(None),
    department: Optional[str] = Form(None),
    source: Optional[str] = Form(None),
    profile: Optional[str] = Form(None),
    client: Dict[str, Any] = Depends(get_api_client),
):
    """
    Universal file upload endpoint - any application can use this, no
    Nextcloud/Ansible-SSH relationship required. The file's bytes are
    streamed directly onto THIS Scanner Server's own staging volume
    (see docker-compose.yml: `api` now shares the `staging_data` volume
    with `worker`, read-write, specifically for this endpoint - the only
    deliberate exception to "api never touches local scan state").

    Synchronous mode: pass ?wait=true or header X-Scan-Wait: true to
    block until a terminal result (or a configurable timeout - see
    SYNC_WAIT_DEFAULT_TIMEOUT_SECONDS/?timeout=). On timeout, returns the
    CURRENT (non-terminal) status - never fabricates CLEAN.
    """
    require_permission(client, "scan.upload")

    if not _upload_rate_limit_ok(str(client["id"])):
        return _error(status.HTTP_429_TOO_MANY_REQUESTS, "Upload rate limit exceeded")

    if not username.strip():
        return _error(status.HTTP_400_BAD_REQUEST, "username is required")

    sys_settings = db.get_system_settings()
    max_size = int(sys_settings.get("max_file_size_bytes", settings.max_file_size))

    # --- resolve scanner profile: server decides, client can only pick
    #     from what it's allowed to (see auth_apikey / api_clients.scanner_profile_id) ---
    resolved_profile_id, profile_error = _resolve_profile_for_client(client, profile)
    if profile_error:
        return _error(status.HTTP_403_FORBIDDEN, profile_error)

    # --- stream the upload to a temp file, hashing as we go, enforcing
    #     the size limit WHILE reading (not after) ---
    request_id = uuid.uuid4().hex
    try:
        staged = await stream_upload_to_staging(file, max_size, request_id)
    except UploadTooLarge:
        return _error(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "File exceeds maximum allowed size")
    except UploadEmpty:
        return _error(status.HTTP_400_BAD_REQUEST, "Uploaded file is empty")

    tmp_path = staged["tmp_path"]
    original_filename = staged["original_filename"]
    total_size = staged["total_size"]

    extension = Path(original_filename).suffix.lower().lstrip(".")
    mime_type = detect_mime_type(str(tmp_path), original_filename)

    policy_error = check_file_type_policy(sys_settings, extension, mime_type)
    if policy_error:
        _rmtree_quiet(staged["tmp_dir"])
        return _error(status.HTTP_400_BAD_REQUEST, policy_error)

    sha256_hex = staged["sha256_hex"]
    md5_hex = staged["md5_hex"]
    source_application = (source or client.get("name") or "api").strip()

    try:
        row = db.create_scan(
            request_id=request_id,
            username=username.strip(),
            nextcloud_host="",
            nextcloud_file_path="",
            relative_path=original_filename,
            filename=original_filename,
            original_size=total_size,
            sha256=sha256_hex,
            user_id=user_id,
            email=email,
            department=department,
            source_application=source_application,
            api_client_id=client["id"],
            mime_type=mime_type,
            md5=md5_hex,
            original_filename=original_filename,
            extension=extension or None,
            scanner_profile_id=resolved_profile_id,
            transfer_mode="direct_upload",
        )
    except Exception:
        logger.exception(json.dumps({"event": "create_scan_db_error", "request_id": request_id}))
        _rmtree_quiet(staged["tmp_dir"])
        return _error(status.HTTP_503_SERVICE_UNAVAILABLE, "Scanner unavailable")

    scan_id = str(row["id"])

    # Moves the hashed temp file into its real, scan_id-scoped staging
    # location - the worker (via ansible/scan_uploaded_file.yml) expects
    # to find it at STAGING_BASE/<scan_id>/input/<filename>.
    finalize_staged_upload(scan_id, staged)

    logger.info(json.dumps({
        "event": "upload_received", "scan_id": scan_id, "request_id": request_id,
        "api_client": client["name"], "username": username, "filename": original_filename,
        "size": total_size, "sha256": sha256_hex,
    }))

    wants_wait = _wants_sync_wait(request)
    if wants_wait:
        timeout = _resolve_wait_timeout(request)
        final_row = await _poll_until_terminal(scan_id, timeout)
        return _build_upload_response(final_row, status_code_hint=True)

    return {"scan_id": scan_id, "status": "QUEUED", "message": "File accepted for scanning"}


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str, client: Dict[str, Any] = Depends(get_api_client)):
    require_permission(client, "scan.read")
    row = _get_scan_with_ownership_check(scan_id, client)
    if isinstance(row, JSONResponse):
        return row
    return _build_upload_response(row)


@router.get("/scans/{scan_id}/results")
async def get_scan_results(scan_id: str, client: Dict[str, Any] = Depends(get_api_client)):
    require_permission(client, "scan.read")
    row = _get_scan_with_ownership_check(scan_id, client)
    if isinstance(row, JSONResponse):
        return row
    results = db.get_scan_results(scan_id)
    return {
        "scan_id": scan_id,
        "results": [
            {
                "scanner": r["scanner_name"],
                "scanner_version": r["scanner_version"],
                "status": r["status"],
                "threat": r["threat"],
                "duration_ms": r["duration_ms"],
            }
            for r in results
        ],
    }


@router.get("/scanners")
async def list_scanners_public(client: Dict[str, Any] = Depends(get_api_client)):
    """Deliberately minimal - never exposes docker_image/scan_command/env_vars
    to normal API clients (administrative detail, see /scanners in the panel)."""
    scanners = db.list_scanners(enabled_only=True)
    return {"scanners": [{"name": s["name"], "slug": s["slug"], "version": s["version"]} for s in scanners]}


@router.get("/profiles")
async def list_profiles_public(client: Dict[str, Any] = Depends(get_api_client)):
    profiles = [p for p in db.list_profiles() if p["enabled"]]
    return {
        "profiles": [
            {"name": p["name"], "slug": p["slug"], "description": p["description"]}
            for p in profiles
        ]
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_profile_for_client(client: Dict[str, Any], requested_slug: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """
    Returns (profile_id_or_None, error_message_or_None). None profile_id
    with no error means "use the system default" (resolved later, in
    api/scanner.py, at scan time). The client can never choose an
    arbitrary scanner list directly - only a named, admin-created profile.
    """
    pinned_id = client.get("scanner_profile_id")
    if pinned_id:
        if requested_slug:
            pinned = db.get_profile(pinned_id)
            if pinned and pinned["slug"] != requested_slug:
                return None, (
                    f"API client '{client['name']}' is restricted to the "
                    f"'{pinned['slug']}' scanner profile and cannot request '{requested_slug}'"
                )
        return pinned_id, None

    if requested_slug:
        profiles = {p["slug"]: p for p in db.list_profiles()}
        chosen = profiles.get(requested_slug)
        if chosen is None or not chosen["enabled"]:
            return None, f"Unknown or disabled scanner profile: {requested_slug!r}"
        return chosen["id"], None

    return None, None


def check_file_type_policy(sys_settings: Dict[str, Any], extension: str, mime_type: str) -> Optional[str]:
    allowed_ext = sys_settings.get("allowed_extensions") or []
    blocked_ext = sys_settings.get("blocked_extensions") or []
    allowed_mime = sys_settings.get("allowed_mime_types") or []
    blocked_mime = sys_settings.get("blocked_mime_types") or []

    if extension and extension in blocked_ext:
        return f"File extension '.{extension}' is blocked by policy"
    if allowed_ext and extension not in allowed_ext:
        return f"File extension '.{extension}' is not in the allowed list"
    if mime_type in blocked_mime:
        return f"MIME type '{mime_type}' is blocked by policy"
    if allowed_mime and mime_type not in allowed_mime:
        return f"MIME type '{mime_type}' is not in the allowed list"
    return None


def _wants_sync_wait(request: Request) -> bool:
    if request.query_params.get("wait", "").lower() == "true":
        return True
    return request.headers.get("x-scan-wait", "").lower() == "true"


def _resolve_wait_timeout(request: Request) -> float:
    raw = request.query_params.get("timeout")
    default = settings.sync_wait_default_timeout_seconds
    maximum = settings.sync_wait_max_timeout_seconds
    try:
        value = float(raw) if raw else default
    except ValueError:
        value = default
    return max(1.0, min(value, maximum))


async def _poll_until_terminal(scan_id: str, timeout_seconds: float) -> Dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    terminal = {"CLEAN", "INFECTED", "ERROR", "ENCRYPTED", "CLEANUP_FAILED"}
    while True:
        row = db.get_scan(scan_id)
        if row is None or row["status"] in terminal:
            return row or {"id": scan_id, "status": "ERROR", "allowed": False, "error_message": "Scan disappeared"}
        if time.monotonic() >= deadline:
            return row  # still in progress - report the real status, never fabricate CLEAN
        await asyncio.sleep(settings.sync_wait_poll_interval_seconds)


def _get_scan_with_ownership_check(scan_id: str, client: Dict[str, Any]):
    try:
        uuid.UUID(scan_id)
    except ValueError:
        return _error(status.HTTP_400_BAD_REQUEST, "Invalid scan_id")

    row = db.get_scan(scan_id)
    if row is None:
        return _error(status.HTTP_404_NOT_FOUND, "Scan not found")

    permissions = client.get("permissions") or []
    if "scan.read_all" not in permissions and str(row.get("api_client_id")) != str(client["id"]):
        # Deliberately the SAME 404 as "not found" - do not confirm to a
        # client that a scan_id it doesn't own exists at all.
        return _error(status.HTTP_404_NOT_FOUND, "Scan not found")

    return row


def _build_upload_response(row: Dict[str, Any], status_code_hint: bool = False) -> Dict[str, Any]:
    scan_status = row["status"]
    body: Dict[str, Any] = {
        "scan_id": str(row["id"]),
        "status": scan_status,
        "filename": row.get("filename"),
        "username": row.get("username"),
        "sha256": row.get("sha256"),
        "size": row.get("original_size"),
    }

    if scan_status == "CLEAN":
        body["allowed"] = True
        body["scanners"] = _scanner_summaries(row["id"])
    elif scan_status == "INFECTED":
        body["allowed"] = False
        results = db.get_scan_results(row["id"])
        body["threats"] = sorted({r["threat"] for r in results if r["status"] == "INFECTED" and r["threat"]})
        body["scanners"] = _scanner_summaries(row["id"])
    elif scan_status == "ENCRYPTED":
        body["allowed"] = bool(row.get("allowed"))
    elif scan_status in ("ERROR", "CLEANUP_FAILED"):
        body["allowed"] = False
        body["message"] = row.get("error_message") or "Scan failed"
    else:
        body["allowed"] = None  # still in progress

    return body


def _scanner_summaries(scan_id: str):
    return [
        {"name": r["scanner_name"], "status": r["status"], "threat": r["threat"]}
        for r in db.get_scan_results(scan_id)
    ]


def _rmtree_quiet(path: Path) -> None:
    import shutil
    shutil.rmtree(path, ignore_errors=True)
