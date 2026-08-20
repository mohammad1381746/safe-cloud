from __future__ import annotations

import math
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

import db
from panel.auth import require_login_or_redirect
from panel.csrf import get_csrf_token, verify_csrf

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
# Lets base.html's logout form embed a valid CSRF token on EVERY
# authenticated page, including ones whose own route doesn't explicitly
# pass a `csrf_token` value into its context (e.g. dashboard, scans list)
# - named differently from the `csrf_token` context key some routes DO
# set explicitly for their own forms (scan_detail.html etc), so there is
# no shadowing ambiguity between the two.
templates.env.globals["csrf_token_for"] = get_csrf_token

router = APIRouter()

_STATUS_BADGE = {
    "CLEAN": "success",
    "INFECTED": "danger",
    "ERROR": "danger",
    "CLEANUP_FAILED": "warning",
    "ENCRYPTED": "warning",
    "QUARANTINED": "warning",
    "SCANNING": "info",
    "TRANSFERRING": "info",
    "VALIDATING": "info",
    "RECEIVED": "secondary",
}


def _status_badge(status: str) -> str:
    return _STATUS_BADGE.get(status, "secondary")


templates.env.filters["status_badge"] = _status_badge

_PAGE_SIZE = 25


@router.get("/dashboard")
async def dashboard(request: Request):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect

    stats = db.get_dashboard_stats()
    recent, _ = db.list_scans(page=1, page_size=10)
    return templates.TemplateResponse(request, "dashboard.html", {
        "stats": stats,
        "recent": recent,
        "scans_over_time": db.get_scans_over_time(14),
        "top_users": db.get_top_users(8),
        "scans_by_source": db.get_scans_by_source(8),
        "scans_by_scanner": db.get_scans_by_scanner(8),
        "top_threats": db.get_top_threats(8),
    })


@router.get("/scans")
async def scans_list(
    request: Request,
    page: int = 1,
    status: Optional[str] = None,
    username: Optional[str] = None,
    hostname: Optional[str] = None,
    source: Optional[str] = None,
    antivirus: Optional[str] = None,
    sha256: Optional[str] = None,
    search: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect

    rows, total, page = _query_scans(page, status, username, hostname, source, antivirus, sha256, search, date_from, date_to)
    total_pages = max(1, math.ceil(total / _PAGE_SIZE))

    return templates.TemplateResponse(request, "scans.html", {
        "scans": rows,
        "total": total,
        "page": page,
        "total_pages": total_pages,
        "scanners": db.list_scanners(),
        "filters": {
            "status": status or "", "username": username or "", "hostname": hostname or "",
            "source": source or "", "antivirus": antivirus or "", "sha256": sha256 or "",
            "search": search or "", "date_from": date_from or "", "date_to": date_to or "",
        },
    })


@router.get("/scans/table")
async def scans_table_partial(
    request: Request,
    page: int = 1,
    status: Optional[str] = None,
    username: Optional[str] = None,
    hostname: Optional[str] = None,
    source: Optional[str] = None,
    antivirus: Optional[str] = None,
    sha256: Optional[str] = None,
    search: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
):
    """HTMX partial (just the <tbody> rows) - the /scans page polls this
    every few seconds so in-flight scans visibly move through
    RECEIVED -> ... -> CLEAN/INFECTED/ERROR without a full page reload."""
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect

    rows, _, _ = _query_scans(page, status, username, hostname, source, antivirus, sha256, search, date_from, date_to)
    return templates.TemplateResponse(request, "_scans_table_rows.html", {"scans": rows})


@router.get("/scans/{scan_id}")
async def scan_detail(request: Request, scan_id: str):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect

    row = db.get_scan(scan_id)
    if row is None:
        return templates.TemplateResponse(
            request, "scan_not_found.html", {"scan_id": scan_id}, status_code=404,
        )

    parent = db.get_scan(row["parent_scan_id"]) if row.get("parent_scan_id") else None

    return templates.TemplateResponse(request, "scan_detail.html", {
        "scan": row,
        "scan_results": db.get_scan_results(scan_id),
        "parent_scan": parent,
        "child_scans": db.get_child_scans(scan_id),
        "csrf_token": get_csrf_token(request),
    })


@router.post("/scans/{scan_id}/rescan")
async def rescan(request: Request, scan_id: str):
    redirect = require_login_or_redirect(request)
    if redirect:
        return redirect
    form = await request.form()
    verify_csrf(request, form.get("csrf_token"))

    original = db.get_scan(scan_id)
    if original is None:
        return RedirectResponse(url="/scans", status_code=303)

    # Creates a brand-new scan row/scan_id referencing the original via
    # parent_scan_id - the ORIGINAL result is never modified. Re-uses the
    # same transfer_mode: for ansible_fetch, the worker re-fetches fresh
    # from the Nextcloud host (re-validates the file still exists there
    # and still hashes the same); for direct_upload, there's no original
    # file left to re-fetch (staging was already cleaned up), so a
    # re-scan of a direct upload is only meaningful while evidence was
    # retained (RETAIN_INFECTED_COPY/quarantine) - otherwise it will
    # correctly fail with "file not found" rather than fabricating a result.
    new_request_id = uuid.uuid4().hex
    new_row = db.create_scan(
        request_id=new_request_id,
        username=original["username"],
        nextcloud_host=original["nextcloud_host"],
        nextcloud_file_path=original["nextcloud_file_path"],
        relative_path=original["relative_path"],
        filename=original["filename"],
        original_size=original["original_size"],
        sha256=original["sha256"],
        user_id=original.get("user_id"),
        email=original.get("email"),
        department=original.get("department"),
        source_application=original.get("source_application", "nextcloud"),
        api_client_id=original.get("api_client_id"),
        mime_type=original.get("mime_type"),
        md5=original.get("md5"),
        original_filename=original.get("original_filename"),
        extension=original.get("extension"),
        scanner_profile_id=original.get("scanner_profile_id"),
        transfer_mode=original.get("transfer_mode", "ansible_fetch"),
        parent_scan_id=scan_id,
    )
    db.record_audit(
        actor=request.session.get("username", "admin"),
        action="scan_manually_rerun",
        object_type="scan",
        object_id=str(new_row["id"]),
        ip_address=request.client.host if request.client else None,
        metadata={"parent_scan_id": scan_id},
    )
    return RedirectResponse(url=f"/scans/{new_row['id']}", status_code=303)


def _query_scans(page, status, username, hostname, source, antivirus, sha256, search, date_from, date_to):
    page = max(page, 1)
    rows, total = db.list_scans(
        page=page,
        page_size=_PAGE_SIZE,
        status=status or None,
        username=username or None,
        hostname=hostname or None,
        source=source or None,
        antivirus=antivirus or None,
        sha256=sha256 or None,
        search=search or None,
        date_from=_parse_date(date_from),
        date_to=_parse_date(date_to, end_of_day=True),
    )
    return rows, total, page


def _parse_date(value: Optional[str], *, end_of_day: bool = False) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return None
    if end_of_day:
        dt = dt.replace(hour=23, minute=59, second=59)
    return dt
