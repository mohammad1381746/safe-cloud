from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import defaultdict
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

import db
from config import settings
from panel.csrf import get_csrf_token

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.globals["csrf_token_for"] = get_csrf_token  # see panel/routes.py for why

router = APIRouter()

_PBKDF2_ITERATIONS_DEFAULT = 260_000

# --- login lockout: in-process, keyed by (username, client IP) ---
_MAX_FAILED_ATTEMPTS = 5
_LOCKOUT_SECONDS = 900  # 15 minutes
_failed_attempts: Dict[str, List[float]] = defaultdict(list)
_lockout_lock = Lock()


def _lockout_key(request: Request, username: str) -> str:
    ip = request.client.host if request.client else "unknown"
    return f"{username}:{ip}"


def _is_locked_out(key: str) -> bool:
    now = time.monotonic()
    with _lockout_lock:
        attempts = _failed_attempts[key]
        attempts[:] = [t for t in attempts if now - t < _LOCKOUT_SECONDS]
        return len(attempts) >= _MAX_FAILED_ATTEMPTS


def _record_failed_attempt(key: str) -> None:
    with _lockout_lock:
        _failed_attempts[key].append(time.monotonic())


def _clear_failed_attempts(key: str) -> None:
    with _lockout_lock:
        _failed_attempts.pop(key, None)


def hash_password(password: str, *, iterations: int = _PBKDF2_ITERATIONS_DEFAULT) -> str:
    """
    Produces a self-describing hash string: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>.
    Uses only the Python standard library (hashlib.pbkdf2_hmac) rather
    than adding a bcrypt/argon2 dependency - PBKDF2-HMAC-SHA256 is a
    NIST-approved KDF and adequate for a single admin account on an
    internal tool. Used to generate PANEL_ADMIN_PASSWORD_HASH - see
    README "Management panel setup".
    """
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, iterations_s, salt, hash_hex = encoded.split("$", 3)
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    try:
        iterations = int(iterations_s)
    except ValueError:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations)
    return hmac.compare_digest(candidate.hex(), hash_hex)


def is_authenticated(request: Request) -> bool:
    return bool(request.session.get("authenticated"))


def require_login_or_redirect(request: Request) -> Optional[RedirectResponse]:
    """
    Call at the top of every protected panel route:

        redirect = require_login_or_redirect(request)
        if redirect:
            return redirect

    FastAPI dependencies can't cleanly short-circuit a route with a
    redirect response, so protected routes check this explicitly instead
    of relying on Depends() + an exception handler.
    """
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)
    return None


@router.get("/login")
async def login_form(request: Request):
    if is_authenticated(request):
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login")
async def login_submit(request: Request):
    form = await request.form()
    username = str(form.get("username", ""))
    password = str(form.get("password", ""))
    client_ip = request.client.host if request.client else "unknown"
    key = _lockout_key(request, username)

    if _is_locked_out(key):
        db.record_audit(actor=username or "unknown", action="login_locked_out", ip_address=client_ip)
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": f"Too many failed attempts. Try again in up to {_LOCKOUT_SECONDS // 60} minutes."},
            status_code=429,
        )

    valid_username = hmac.compare_digest(username, settings.panel_admin_username)
    valid_password = verify_password(password, settings.panel_admin_password_hash)

    if valid_username and valid_password:
        _clear_failed_attempts(key)
        request.session.clear()
        request.session["authenticated"] = True
        request.session["username"] = username
        db.record_audit(actor=username, action="login", ip_address=client_ip)
        return RedirectResponse(url="/dashboard", status_code=303)

    _record_failed_attempt(key)
    db.record_audit(actor=username or "unknown", action="login_failed", ip_address=client_ip)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"error": "Invalid username or password"},
        status_code=401,
    )


@router.post("/logout")
async def logout(request: Request):
    username = request.session.get("username", "unknown")
    client_ip = request.client.host if request.client else "unknown"
    request.session.clear()
    db.record_audit(actor=username, action="logout", ip_address=client_ip)
    return RedirectResponse(url="/login", status_code=303)


@router.get("/")
async def root(request: Request):
    if is_authenticated(request):
        return RedirectResponse(url="/dashboard", status_code=303)
    return RedirectResponse(url="/login", status_code=303)
