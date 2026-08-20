from __future__ import annotations

import json as _json
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

import db
from panel.auth import require_login_or_redirect
from panel.csrf import get_csrf_token, verify_csrf
from scanners import ScannerConfigError, validate_scanner_config

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.globals["csrf_token_for"] = get_csrf_token  # see panel/routes.py for why
router = APIRouter()


@router.get("/scanners")
async def scanners_list(request: Request):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(request, "scanners.html", {"scanners": db.list_scanners()})


@router.get("/scanners/new")
async def scanner_new_form(request: Request):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(request, "scanner_form.html", {
        "scanner": None, "csrf_token": get_csrf_token(request), "error": None,
    })


@router.post("/scanners/new")
async def scanner_new_submit(request: Request):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    form = await request.form()
    verify_csrf(request, form.get("csrf_token"))
    data = _parse_scanner_form(form)
    try:
        cleaned = validate_scanner_config(data)
    except ScannerConfigError as exc:
        return templates.TemplateResponse(request, "scanner_form.html", {
            "scanner": data, "csrf_token": get_csrf_token(request), "error": str(exc),
        }, status_code=400)

    row = db.create_scanner(**cleaned)
    _audit(request, "scanner_created", "scanner", str(row["id"]), {"name": cleaned["name"]})
    return RedirectResponse(url="/scanners", status_code=303)


@router.get("/scanners/{scanner_id}/edit")
async def scanner_edit_form(request: Request, scanner_id: str):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    scanner = db.get_scanner(scanner_id)
    if scanner is None:
        return RedirectResponse(url="/scanners", status_code=303)
    return templates.TemplateResponse(request, "scanner_form.html", {
        "scanner": scanner, "csrf_token": get_csrf_token(request), "error": None,
    })


@router.post("/scanners/{scanner_id}/edit")
async def scanner_edit_submit(request: Request, scanner_id: str):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    form = await request.form()
    verify_csrf(request, form.get("csrf_token"))

    existing = db.get_scanner(scanner_id)
    if existing is None:
        return RedirectResponse(url="/scanners", status_code=303)

    data = _parse_scanner_form(form)
    try:
        cleaned = validate_scanner_config(data)
    except ScannerConfigError as exc:
        return templates.TemplateResponse(request, "scanner_form.html", {
            "scanner": {**existing, **data}, "csrf_token": get_csrf_token(request), "error": str(exc),
        }, status_code=400)

    was_enabled = existing["enabled"]
    db.update_scanner(scanner_id, **cleaned)
    _audit(request, "scanner_modified", "scanner", scanner_id)
    if was_enabled != cleaned["enabled"]:
        _audit(request, "scanner_enabled" if cleaned["enabled"] else "scanner_disabled", "scanner", scanner_id)
    return RedirectResponse(url="/scanners", status_code=303)


@router.post("/scanners/{scanner_id}/delete")
async def scanner_delete(request: Request, scanner_id: str):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    form = await request.form()
    verify_csrf(request, form.get("csrf_token"))
    db.delete_scanner(scanner_id)
    _audit(request, "scanner_deleted", "scanner", scanner_id)
    return RedirectResponse(url="/scanners", status_code=303)


def _parse_scanner_form(form) -> Dict[str, Any]:
    try:
        scan_command = _json.loads(form.get("scan_command_json") or "[]")
    except _json.JSONDecodeError:
        scan_command = form.get("scan_command_json")  # kept as-is (invalid) so validate_scanner_config reports it
    try:
        env_vars = _json.loads(form.get("env_vars_json") or "{}")
    except _json.JSONDecodeError:
        env_vars = {}

    return {
        "name": form.get("name", ""),
        "slug": form.get("slug", ""),
        "description": form.get("description", ""),
        "enabled": form.get("enabled") == "on",
        "docker_image": form.get("docker_image", ""),
        "scan_command": scan_command,
        "env_vars": env_vars,
        "result_parser": form.get("result_parser", "clamav_wrapper_json"),
        "timeout_seconds": form.get("timeout_seconds", 120),
        "cpu_limit": form.get("cpu_limit", 1.0),
        "memory_limit_mb": form.get("memory_limit_mb", 512),
    }


def _audit(request: Request, action: str, object_type: str, object_id: str, metadata: Dict[str, Any] | None = None) -> None:
    db.record_audit(
        actor=request.session.get("username", "admin"),
        action=action,
        object_type=object_type,
        object_id=object_id,
        ip_address=request.client.host if request.client else None,
        metadata=metadata or {},
    )
