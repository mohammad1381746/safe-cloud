from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

import db
from auth_apikey import generate_api_key
from panel.auth import require_login_or_redirect
from panel.csrf import get_csrf_token, verify_csrf
from policy import ENCRYPTED_POLICIES

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.globals["csrf_token_for"] = get_csrf_token  # see panel/routes.py for why
router = APIRouter()

_ENCRYPTED_CATEGORIES = [
    ("archive_password_protected", "Password-protected archive (ZIP/RAR/7z)"),
    ("pdf_encrypted", "Encrypted PDF"),
    ("office_encrypted", "Encrypted Office document"),
    ("unknown_encryption", "Unknown encryption (can't be determined)"),
    ("default", "Default (fallback for anything not listed above)"),
]


@router.get("/settings")
async def settings_index(request: Request):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(request, "settings_index.html", {})


# --- Encrypted file policy -------------------------------------------------

@router.get("/settings/encrypted-files")
async def encrypted_files_form(request: Request):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(request, "settings_encrypted_files.html", {
        "categories": _ENCRYPTED_CATEGORIES,
        "policies": db.get_encrypted_policies(),
        "options": ENCRYPTED_POLICIES,
        "csrf_token": get_csrf_token(request),
        "saved": False,
    })


@router.post("/settings/encrypted-files")
async def encrypted_files_submit(request: Request):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    form = await request.form()
    verify_csrf(request, form.get("csrf_token"))

    for category, _label in _ENCRYPTED_CATEGORIES:
        value = form.get(f"policy_{category}")
        if value in ENCRYPTED_POLICIES:
            db.set_encrypted_policy(category, value)

    _audit(request, "encrypted_policy_changed", "encrypted_file_policies", None,
           {c: form.get(f"policy_{c}") for c, _ in _ENCRYPTED_CATEGORIES})

    return templates.TemplateResponse(request, "settings_encrypted_files.html", {
        "categories": _ENCRYPTED_CATEGORIES,
        "policies": db.get_encrypted_policies(),
        "options": ENCRYPTED_POLICIES,
        "csrf_token": get_csrf_token(request),
        "saved": True,
    })


# --- API clients -------------------------------------------------------

@router.get("/settings/api-clients")
async def api_clients_list(request: Request):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    new_key = request.session.pop("new_api_key", None)
    return templates.TemplateResponse(request, "settings_api_clients.html", {
        "clients": db.list_api_clients(),
        "profiles": db.list_profiles(),
        "csrf_token": get_csrf_token(request),
        "new_key": new_key,
    })


@router.post("/settings/api-clients/new")
async def api_client_create(request: Request):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    form = await request.form()
    verify_csrf(request, form.get("csrf_token"))

    name = form.get("name", "").strip()
    if not name:
        return RedirectResponse(url="/settings/api-clients", status_code=303)

    permissions = form.getlist("permissions") or ["scan.upload", "scan.read"]
    scanner_profile_id = form.get("scanner_profile_id") or None

    full_key, prefix, key_hash = generate_api_key()
    row = db.create_api_client(
        name=name,
        description=form.get("description", ""),
        owner=form.get("owner", ""),
        enabled=True,
        key_prefix=prefix,
        key_hash=key_hash,
        scanner_profile_id=scanner_profile_id,
        permissions=permissions,
    )
    # The full key is shown EXACTLY ONCE - stashed in the session for the
    # very next page render only, then popped (see api_clients_list above).
    request.session["new_api_key"] = full_key
    _audit(request, "api_key_created", "api_client", str(row["id"]), {"name": name})
    return RedirectResponse(url="/settings/api-clients", status_code=303)


@router.post("/settings/api-clients/{client_id}/revoke")
async def api_client_revoke(request: Request, client_id: str):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    form = await request.form()
    verify_csrf(request, form.get("csrf_token"))
    db.revoke_api_client(client_id)
    _audit(request, "api_key_revoked", "api_client", client_id)
    return RedirectResponse(url="/settings/api-clients", status_code=303)


@router.post("/settings/api-clients/{client_id}/rotate")
async def api_client_rotate(request: Request, client_id: str):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    form = await request.form()
    verify_csrf(request, form.get("csrf_token"))
    full_key, prefix, key_hash = generate_api_key()
    db.rotate_api_client_key(client_id, prefix, key_hash)
    request.session["new_api_key"] = full_key
    _audit(request, "api_key_rotated", "api_client", client_id)
    return RedirectResponse(url="/settings/api-clients", status_code=303)


# --- Security / system settings ----------------------------------------

@router.get("/settings/security")
async def security_form(request: Request):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(request, "settings_security.html", {
        "settings": db.get_system_settings(),
        "csrf_token": get_csrf_token(request),
        "saved": False,
    })


@router.post("/settings/security")
async def security_submit(request: Request):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    form = await request.form()
    verify_csrf(request, form.get("csrf_token"))

    def _int(name: str, default: int) -> int:
        try:
            return int(form.get(name, default))
        except (TypeError, ValueError):
            return default

    def _csv(name: str):
        raw = form.get(name, "") or ""
        return [v.strip().lower() for v in raw.split(",") if v.strip()]

    partial: Dict[str, Any] = {
        "scan_history_retention_days": _int("scan_history_retention_days", 365),
        "staging_retention_hours": _int("staging_retention_hours", 24),
        "quarantine_retention_days": _int("quarantine_retention_days", 30),
        "audit_log_auto_prune": form.get("audit_log_auto_prune") == "on",
        "rate_limit_uploads_per_minute": _int("rate_limit_uploads_per_minute", 30),
        "rate_limit_requests_per_minute": _int("rate_limit_requests_per_minute", 120),
        "max_file_size_bytes": _int("max_file_size_bytes", 5368709120),
        "allowed_extensions": _csv("allowed_extensions"),
        "blocked_extensions": _csv("blocked_extensions"),
        "allowed_mime_types": _csv("allowed_mime_types"),
        "blocked_mime_types": _csv("blocked_mime_types"),
    }
    db.update_system_settings(partial)
    _audit(request, "system_settings_changed", "system_settings", None, partial)

    return templates.TemplateResponse(request, "settings_security.html", {
        "settings": db.get_system_settings(),
        "csrf_token": get_csrf_token(request),
        "saved": True,
    })


# --- Audit log -----------------------------------------------------------

@router.get("/audit")
async def audit_log_view(request: Request, page: int = 1, actor: str = "", action: str = ""):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    rows, total = db.list_audit_log(page=page, actor=actor or None, action=action or None)
    return templates.TemplateResponse(request, "audit.html", {
        "entries": rows, "total": total, "page": page,
        "filters": {"actor": actor, "action": action},
    })


def _audit(request: Request, action: str, object_type: str, object_id: str | None, metadata: Dict[str, Any] | None = None) -> None:
    db.record_audit(
        actor=request.session.get("username", "admin"),
        action=action,
        object_type=object_type,
        object_id=object_id,
        ip_address=request.client.host if request.client else None,
        metadata=metadata or {},
    )
