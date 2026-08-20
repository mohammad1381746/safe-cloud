from __future__ import annotations

import json
import logging
import time
import uuid
from collections import defaultdict, deque
from threading import Lock
from typing import Deque, Dict

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

import db
from config import settings
from logging_config import configure_logging
from models import ScanRequest
from panel import router as panel_router
from routes_upload import router as upload_router
from security import (
    HostNotAllowedError,
    PathNotAllowedError,
    normalize_and_validate_path,
    resolve_nextcloud_host,
    validate_username,
    verify_bearer_token,
)

configure_logging()
logger = logging.getLogger("scanner.api")

# DOCS_ENABLED is an env var, not a system_settings DB row - FastAPI
# registers /docs and /redoc at app-construction time, before any DB
# query could inform the decision, so toggling it always requires a
# restart regardless of where the flag lives.
app = FastAPI(
    title="Nextcloud Upload Scanner API",
    version="2.0.0",
    docs_url="/docs" if settings.docs_enabled else None,
    redoc_url="/redoc" if settings.docs_enabled else None,
    openapi_url="/openapi.json" if settings.docs_enabled else None,
)

# --- CORS: strict by default (empty allowlist = no cross-origin requests) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# --- Session cookies for the management panel (see panel/auth.py) ---
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.panel_session_secret,
    https_only=settings.panel_session_cookie_secure,
    max_age=settings.panel_session_max_age_seconds,
)


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    """Rejects oversized request bodies before they're parsed, for the
    small-JSON-only legacy endpoints (POST /api/v1/scan and friends -
    see README section 1a). The universal upload API
    (POST /api/v1/files/upload) and the panel's manual upload
    (POST /upload) legitimately carry actual file bytes up to
    settings.max_file_size (default 5 GiB) - they're exempted here and
    enforce their OWN size limit themselves, mid-stream, byte-by-byte, as
    the upload is read (see routes_upload.py::stream_upload_to_staging) -
    a Content-Length pre-check would just apply the wrong, far smaller
    limit to them, which is exactly the "Request Entity Too Large" bug
    this exemption fixes."""

    _EXEMPT_PREFIXES = ("/api/v1/files/upload", "/upload")

    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith(self._EXEMPT_PREFIXES):
            return await call_next(request)
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > settings.max_request_body_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={"status": "ERROR", "allowed": False, "message": "Request body too large"},
                    )
            except ValueError:
                pass
        return await call_next(request)


app.add_middleware(MaxBodySizeMiddleware)


class RateLimiter:
    """
    In-process sliding-window rate limiter keyed by (token fingerprint,
    client IP). Single-instance only - if the API is ever scaled
    horizontally behind a load balancer, replace this with a shared store
    (e.g. Redis) keyed the same way. RATE_LIMIT_PER_MINUTE is configurable
    via settings.
    """

    def __init__(self, limit_per_minute: int):
        self.limit = limit_per_minute
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        window_start = now - 60.0
        with self._lock:
            q = self._hits[key]
            while q and q[0] < window_start:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True


rate_limiter = RateLimiter(settings.rate_limit_per_minute)

app.include_router(panel_router)
app.include_router(upload_router)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning(json.dumps({"event": "validation_error", "path": str(request.url.path)}))
    return JSONResponse(
        status_code=400,
        content={"status": "ERROR", "allowed": False, "message": "Invalid request payload"},
    )


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.post("/api/v1/scan", status_code=202)
async def submit_scan(
    payload: ScanRequest,
    request: Request,
    token_fp: str = Depends(verify_bearer_token),
):
    """
    Validates the request synchronously (auth, host allowlist, path
    allowlist, size limit) and, only if everything passes, creates a
    `scans` row and returns 202 immediately - the actual transfer/scan
    happens asynchronously in worker.py. Validation failures never create
    a database row and never touch the Nextcloud host at all (see README
    Test 4: path traversal -> 403, no file transfer attempted).
    """
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"{token_fp}:{client_ip}"

    if not rate_limiter.allow(rate_key):
        logger.warning(json.dumps({"event": "rate_limited", "client_ip": client_ip}))
        return JSONResponse(
            status_code=429,
            content={"status": "ERROR", "allowed": False, "message": "Rate limit exceeded"},
        )

    try:
        validate_username(payload.username)
    except ValueError:
        return JSONResponse(
            status_code=400,
            content={"status": "ERROR", "allowed": False, "message": "Invalid username"},
        )

    if payload.size > settings.max_file_size:
        logger.warning(json.dumps({
            "event": "size_rejected", "hostname": payload.hostname,
            "username": payload.username, "size": payload.size,
        }))
        return JSONResponse(
            status_code=400,
            content={"status": "ERROR", "allowed": False, "message": "File exceeds maximum allowed size"},
        )

    try:
        host_cfg = resolve_nextcloud_host(payload.hostname)
    except HostNotAllowedError as exc:
        logger.warning(json.dumps({
            "event": "host_rejected", "hostname": payload.hostname, "reason": str(exc),
        }))
        return JSONResponse(
            status_code=403,
            content={"status": "ERROR", "allowed": False, "message": "Host is not permitted"},
        )

    try:
        normalized_path = normalize_and_validate_path(payload.file_path, host_cfg.allowed_root)
    except PathNotAllowedError as exc:
        logger.warning(json.dumps({
            "event": "path_rejected", "hostname": payload.hostname, "reason": str(exc),
        }))
        return JSONResponse(
            status_code=403,
            content={"status": "ERROR", "allowed": False, "message": "File path is not permitted"},
        )

    request_id = uuid.uuid4().hex
    filename = normalized_path.rsplit("/", 1)[-1]

    try:
        row = db.create_scan(
            request_id=request_id,
            username=payload.username,
            nextcloud_host=payload.hostname,
            nextcloud_file_path=normalized_path,
            relative_path=payload.relative_path,
            filename=filename,
            original_size=payload.size,
            sha256=payload.sha256,
        )
    except Exception:
        logger.exception(json.dumps({"event": "create_scan_db_error", "request_id": request_id}))
        return JSONResponse(
            status_code=503,
            content={"status": "ERROR", "allowed": False, "message": "Scanner unavailable"},
        )

    logger.info(json.dumps({
        "event": "scan_received",
        "scan_id": str(row["id"]),
        "request_id": request_id,
        "hostname": payload.hostname,
        "username": payload.username,
        "file": payload.relative_path,
    }))

    return {"scan_id": str(row["id"]), "status": "RECEIVED"}


@app.get("/api/v1/scan/{scan_id}")
async def get_scan_status(scan_id: str, token_fp: str = Depends(verify_bearer_token)):
    try:
        uuid.UUID(scan_id)
    except ValueError:
        return JSONResponse(
            status_code=400,
            content={"status": "ERROR", "allowed": False, "message": "Invalid scan_id"},
        )

    row = db.get_scan(scan_id)
    if row is None:
        return JSONResponse(
            status_code=404,
            content={"status": "ERROR", "allowed": False, "message": "Scan not found"},
        )

    return _scan_status_response(row)


def _scan_status_response(row: dict) -> dict:
    status = row["status"]
    body = {"scan_id": str(row["id"]), "status": status}

    if status == "CLEAN":
        body.update(allowed=True, sha256=row["sha256"], filename=row["filename"])
    elif status == "INFECTED":
        body.update(allowed=False, sha256=row["sha256"], threat=row["threat"], filename=row["filename"])
    elif status in ("ERROR", "CLEANUP_FAILED"):
        body.update(allowed=False, message=row.get("error_message") or "Scan failed")
    else:
        body.update(allowed=None)

    return body
