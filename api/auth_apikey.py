from __future__ import annotations

import hashlib
import secrets
from typing import Any, Dict, Optional, Tuple

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

import db

# =============================================================================
# API client (application-facing) authentication - separate from the
# admin panel's session-cookie auth (panel/auth.py) and from the
# existing Nextcloud bash hook's static SCANNER_API_TOKEN
# (security.py::verify_bearer_token, unchanged, still used by
# /api/v1/scan). This module authenticates callers of the NEW universal
# upload API (/api/v1/files/upload and friends) against per-client keys
# stored in the `api_clients` table.
#
# Keys are never stored in plaintext - only a SHA-256 hash. This is
# deliberately NOT a slow password KDF (PBKDF2/bcrypt/argon2): API keys,
# unlike admin passwords, are already high-entropy random secrets
# (256 bits here), not something a slow hash is protecting against
# offline guessing - a fast hash is the standard, correct choice for this
# case (the same model Stripe/GitHub/etc use for their API keys).
# =============================================================================

_KEY_PREFIX = "sk_live_"
_bearer_scheme = HTTPBearer(auto_error=False)


def generate_api_key() -> Tuple[str, str, str]:
    """Returns (full_key, display_prefix, key_hash). The full key is
    returned to the caller EXACTLY ONCE (at creation/rotation time) and
    is never persisted or logged anywhere - only its hash is stored."""
    secret = secrets.token_urlsafe(32)
    full_key = f"{_KEY_PREFIX}{secret}"
    display_prefix = full_key[: len(_KEY_PREFIX) + 8]  # e.g. "sk_live_AbCdEfGh" - safe to show in the UI/logs
    key_hash = hash_api_key(full_key)
    return full_key, display_prefix, key_hash


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


async def get_api_client(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> Dict[str, Any]:
    """
    FastAPI dependency for the universal upload API. Validates the
    Authorization: Bearer <api_key> header against `api_clients`, updates
    last_used_at, and returns the client row. Raises 401 for
    missing/invalid/disabled/revoked keys - never distinguishes WHICH of
    those it was in the response, to avoid helping an attacker enumerate
    valid-but-disabled keys.
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API key")

    key_hash = hash_api_key(credentials.credentials)
    client = db.get_api_client_by_key_hash(key_hash)
    if client is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked API key")

    db.touch_api_client_last_used(client["id"])
    return client


def require_permission(client: Dict[str, Any], permission: str) -> None:
    permissions = client.get("permissions") or []
    if permission not in permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"API client '{client['name']}' does not have the '{permission}' permission",
        )
