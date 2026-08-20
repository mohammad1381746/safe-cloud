from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

import db
from config import settings
from encryption_detect import detect_mime_type
from panel.auth import require_login_or_redirect
from panel.csrf import get_csrf_token, verify_csrf
from routes_upload import (
    UploadEmpty,
    UploadTooLarge,
    check_file_type_policy,
    finalize_staged_upload,
    stream_upload_to_staging,
)

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.globals["csrf_token_for"] = get_csrf_token  # see panel/routes.py for why
router = APIRouter()


@router.get("/upload")
async def upload_form(request: Request):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(request, "upload.html", {
        "profiles": [p for p in db.list_profiles() if p["enabled"]],
        "default_username": request.session.get("username", ""),
        "csrf_token": get_csrf_token(request),
        "error": None,
        "form": {},
    })


@router.post("/upload")
async def upload_submit(request: Request):
    """
    The panel's own manual upload path - an authenticated admin dropping a
    file in through the browser rather than a script calling the API.
    Session-authenticated (not API-key), so it skips API-client
    permission/profile-pinning checks entirely (an admin who can reach
    this page already has full panel access), but otherwise goes through
    the EXACT same staging/hashing/size-limit/file-type-policy code as
    POST /api/v1/files/upload (see routes_upload.py) - there is only one
    real upload pipeline, this is just a second front door onto it.
    """
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    form = await request.form()
    verify_csrf(request, form.get("csrf_token"))

    profiles = [p for p in db.list_profiles() if p["enabled"]]
    username = (form.get("username") or "").strip() or request.session.get("username", "admin")
    profile_slug = (form.get("profile") or "").strip()
    upload = form.get("file")

    def _render_error(message: str, status_code: int = 400):
        return templates.TemplateResponse(request, "upload.html", {
            "profiles": profiles,
            "default_username": username,
            "csrf_token": get_csrf_token(request),
            "error": message,
            "form": {"username": username, "profile": profile_slug},
        }, status_code=status_code)

    if upload is None or not getattr(upload, "filename", None):
        return _render_error("Choose a file to upload")

    resolved_profile_id = None
    if profile_slug:
        chosen = next((p for p in profiles if p["slug"] == profile_slug), None)
        if chosen is None:
            return _render_error(f"Unknown or disabled scanner profile: {profile_slug!r}")
        resolved_profile_id = chosen["id"]

    sys_settings = db.get_system_settings()
    max_size = int(sys_settings.get("max_file_size_bytes", settings.max_file_size))

    request_id = uuid.uuid4().hex
    try:
        staged = await stream_upload_to_staging(upload, max_size, request_id)
    except UploadTooLarge:
        return _render_error("File exceeds the maximum allowed size", status_code=413)
    except UploadEmpty:
        return _render_error("Uploaded file is empty")

    original_filename = staged["original_filename"]
    extension = Path(original_filename).suffix.lower().lstrip(".")
    mime_type = detect_mime_type(str(staged["tmp_path"]), original_filename)

    policy_error = check_file_type_policy(sys_settings, extension, mime_type)
    if policy_error:
        import shutil
        shutil.rmtree(staged["tmp_dir"], ignore_errors=True)
        return _render_error(policy_error)

    row = db.create_scan(
        request_id=request_id,
        username=username,
        nextcloud_host="",
        nextcloud_file_path="",
        relative_path=original_filename,
        filename=original_filename,
        original_size=staged["total_size"],
        sha256=staged["sha256_hex"],
        source_application="panel",
        mime_type=mime_type,
        md5=staged["md5_hex"],
        original_filename=original_filename,
        extension=extension or None,
        scanner_profile_id=resolved_profile_id,
        transfer_mode="direct_upload",
    )
    scan_id = str(row["id"])
    finalize_staged_upload(scan_id, staged)

    _audit(request, "manual_upload", "scan", scan_id, {
        "filename": original_filename, "sha256": staged["sha256_hex"], "size": staged["total_size"],
        "on_behalf_of": username,
    })

    return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)


def _audit(request: Request, action: str, object_type: str, object_id: str, metadata: Dict[str, Any] | None = None) -> None:
    db.record_audit(
        actor=request.session.get("username", "admin"),
        action=action,
        object_type=object_type,
        object_id=object_id,
        ip_address=request.client.host if request.client else None,
        metadata=metadata or {},
    )
