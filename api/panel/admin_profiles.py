from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

import db
from panel.auth import require_login_or_redirect
from panel.csrf import get_csrf_token, verify_csrf
from policy import AGGREGATION_POLICIES

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.globals["csrf_token_for"] = get_csrf_token  # see panel/routes.py for why
router = APIRouter()


@router.get("/profiles")
async def profiles_list(request: Request):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(request, "profiles.html", {"profiles": db.list_profiles()})


@router.get("/profiles/new")
async def profile_new_form(request: Request):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(request, "profile_form.html", {
        "profile": None, "selected_scanner_ids": [], "all_scanners": db.list_scanners(),
        "policies": AGGREGATION_POLICIES, "csrf_token": get_csrf_token(request), "error": None,
    })


@router.post("/profiles/new")
async def profile_new_submit(request: Request):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    form = await request.form()
    verify_csrf(request, form.get("csrf_token"))

    error = _validate_profile_form(form)
    if error:
        return templates.TemplateResponse(request, "profile_form.html", {
            "profile": dict(form), "selected_scanner_ids": form.getlist("scanner_ids"),
            "all_scanners": db.list_scanners(), "policies": AGGREGATION_POLICIES,
            "csrf_token": get_csrf_token(request), "error": error,
        }, status_code=400)

    row = db.create_profile(
        name=form.get("name", "").strip(),
        slug=form.get("slug", "").strip().lower(),
        description=form.get("description", ""),
        enabled=form.get("enabled") == "on",
        aggregation_policy=form.get("aggregation_policy", "ALL_MUST_PASS"),
    )
    scanner_ids = _ordered_scanner_ids(form)
    db.set_profile_scanners(row["id"], scanner_ids)
    if form.get("is_default") == "on":
        db.set_default_profile(row["id"])
    _audit(request, "profile_created", "scanner_profile", str(row["id"]), {"name": row["name"]})
    return RedirectResponse(url="/profiles", status_code=303)


@router.get("/profiles/{profile_id}/edit")
async def profile_edit_form(request: Request, profile_id: str):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    profile = db.get_profile(profile_id)
    if profile is None:
        return RedirectResponse(url="/profiles", status_code=303)
    selected = [s["id"] for s in db.get_profile_scanners(profile_id)]
    # get_profile_scanners only returns ENABLED scanners - for the edit
    # form we want the full membership including any disabled ones, so
    # re-derive it directly rather than reusing that helper's filtered view.
    with_disabled = [row["id"] for row in db.list_scanners() if _is_member(profile_id, row["id"])]
    return templates.TemplateResponse(request, "profile_form.html", {
        "profile": profile, "selected_scanner_ids": with_disabled or selected,
        "all_scanners": db.list_scanners(), "policies": AGGREGATION_POLICIES,
        "csrf_token": get_csrf_token(request), "error": None,
    })


@router.post("/profiles/{profile_id}/edit")
async def profile_edit_submit(request: Request, profile_id: str):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    form = await request.form()
    verify_csrf(request, form.get("csrf_token"))

    existing = db.get_profile(profile_id)
    if existing is None:
        return RedirectResponse(url="/profiles", status_code=303)

    error = _validate_profile_form(form, editing=True)
    if error:
        return templates.TemplateResponse(request, "profile_form.html", {
            "profile": {**existing, **dict(form)}, "selected_scanner_ids": form.getlist("scanner_ids"),
            "all_scanners": db.list_scanners(), "policies": AGGREGATION_POLICIES,
            "csrf_token": get_csrf_token(request), "error": error,
        }, status_code=400)

    was_enabled = existing["enabled"]
    db.update_profile(
        profile_id,
        name=form.get("name", "").strip(),
        description=form.get("description", ""),
        enabled=form.get("enabled") == "on",
        aggregation_policy=form.get("aggregation_policy", "ALL_MUST_PASS"),
    )
    db.set_profile_scanners(profile_id, _ordered_scanner_ids(form))
    if form.get("is_default") == "on":
        db.set_default_profile(profile_id)

    _audit(request, "profile_modified", "scanner_profile", profile_id)
    if was_enabled != (form.get("enabled") == "on"):
        _audit(request, "profile_enabled" if form.get("enabled") == "on" else "profile_disabled",
               "scanner_profile", profile_id)
    return RedirectResponse(url="/profiles", status_code=303)


@router.post("/profiles/{profile_id}/delete")
async def profile_delete(request: Request, profile_id: str):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    form = await request.form()
    verify_csrf(request, form.get("csrf_token"))
    db.delete_profile(profile_id)
    _audit(request, "profile_deleted", "scanner_profile", profile_id)
    return RedirectResponse(url="/profiles", status_code=303)


def _validate_profile_form(form, editing: bool = False) -> str | None:
    name = form.get("name", "").strip()
    if not name:
        return "Name is required"
    if not editing:
        slug = form.get("slug", "").strip().lower()
        if not re.match(r"^[a-z0-9][a-z0-9-]{1,62}$", slug):
            return "Slug must be lowercase alphanumeric with hyphens, 2-63 chars"
    policy_value = form.get("aggregation_policy", "")
    if policy_value not in AGGREGATION_POLICIES:
        return f"aggregation_policy must be one of {AGGREGATION_POLICIES}"
    if not form.getlist("scanner_ids"):
        return "Select at least one scanner for this profile"
    return None


def _ordered_scanner_ids(form) -> List[str]:
    ids = form.getlist("scanner_ids")
    orders: Dict[str, int] = {}
    for scanner_id in ids:
        try:
            orders[scanner_id] = int(form.get(f"order_{scanner_id}", 0))
        except (TypeError, ValueError):
            orders[scanner_id] = 0
    return sorted(ids, key=lambda sid: orders.get(sid, 0))


def _is_member(profile_id: str, scanner_id: str) -> bool:
    # Membership check including DISABLED scanners (get_profile_scanners
    # filters those out) - used only to pre-populate the edit form
    # checkboxes correctly.
    with db.pool.connection() as conn:
        row = conn.execute(
            "SELECT 1 FROM scanner_profile_scanners WHERE profile_id = %(p)s AND scanner_id = %(s)s",
            {"p": profile_id, "s": scanner_id},
        ).fetchone()
        return row is not None


def _audit(request: Request, action: str, object_type: str, object_id: str, metadata: Dict[str, Any] | None = None) -> None:
    db.record_audit(
        actor=request.session.get("username", "admin"),
        action=action,
        object_type=object_type,
        object_id=object_id,
        ip_address=request.client.host if request.client else None,
        metadata=metadata or {},
    )
