from __future__ import annotations

import hmac
import secrets

from fastapi import HTTPException, Request, status


def get_csrf_token(request: Request) -> str:
    """Session-bound CSRF token (double-submit pattern). Generated once
    per session and reused - every admin POST form embeds it as a hidden
    field; verify_csrf compares it against the session copy."""
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def verify_csrf(request: Request, submitted_token: str) -> None:
    expected = request.session.get("csrf_token")
    if not expected or not submitted_token or not hmac.compare_digest(expected, submitted_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or missing CSRF token")
