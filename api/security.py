from __future__ import annotations

import hashlib
import hmac
import posixpath
import re
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from config import NextcloudHost, settings

_bearer_scheme = HTTPBearer(auto_error=False)

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,255}$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,255}$")


class PathNotAllowedError(Exception):
    """Raised when a requested file_path is not underneath the requested
    host's allowed_root."""


class HostNotAllowedError(Exception):
    """Raised when a requested hostname is not present in NEXTCLOUD_HOSTS."""


def verify_bearer_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> str:
    """
    FastAPI dependency: validates the Authorization: Bearer header.

    Returns a short, non-reversible fingerprint of the token (safe to log /
    use as a rate-limit key). The raw token itself is never returned,
    logged, or persisted anywhere.
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    supplied = credentials.credentials
    for valid_token in settings.scanner_api_tokens_list:
        if hmac.compare_digest(supplied, valid_token):
            return _token_fingerprint(supplied)

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token")


def _token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


def validate_username(username: str) -> str:
    if not _USERNAME_RE.match(username):
        raise ValueError("Invalid username format")
    return username


def resolve_nextcloud_host(hostname: str) -> NextcloudHost:
    """
    Maps a client-supplied hostname to its NEXTCLOUD_HOSTS entry.

    The client can only ever select from NEXTCLOUD_HOSTS keys - it can
    never supply an ansible_host, ansible_user, inventory path, or any
    other Ansible connection detail. The returned `key` doubles as the
    exact Ansible inventory hostname used for `--limit`; the real SSH
    connection details live only in ansible/inventory.ini, so a
    NEXTCLOUD_HOSTS entry with no matching inventory host fails loudly
    (Ansible's "no hosts matched") instead of connecting anywhere
    unexpected.
    """
    if not _HOSTNAME_RE.match(hostname):
        raise HostNotAllowedError(f"Invalid hostname format: {hostname}")
    mapping = settings.nextcloud_hosts_map
    if hostname not in mapping:
        raise HostNotAllowedError(f"Host not in allowlist: {hostname}")
    return mapping[hostname]


def normalize_and_validate_path(file_path: str, allowed_root: str) -> str:
    """
    Lexically validate and normalize a POSIX path supplied by the client,
    against the ALLOWED_ROOT CONFIGURED FOR THIS SPECIFIC HOST (each
    Nextcloud host in NEXTCLOUD_HOSTS has its own allowed_root - a path
    valid for one host's data directory says nothing about another's).

    This is a defensive PRE-FILTER only. The API/worker process does not
    have filesystem access to the remote Nextcloud host, so it cannot
    resolve symlinks or verify existence locally. Authoritative
    canonicalization (realpath -e) and symlink-attack protection happens
    on the Nextcloud host itself inside ansible/scan_pipeline.yml's first
    play, which does have real filesystem access there.
    """
    if not file_path or "\x00" in file_path:
        raise PathNotAllowedError("Invalid file path")

    if not file_path.startswith("/"):
        raise PathNotAllowedError("file_path must be an absolute path")

    normalized = posixpath.normpath(file_path)

    segments = normalized.split("/")
    if ".." in segments:
        raise PathNotAllowedError("Path traversal ('..') is not allowed")

    root = posixpath.normpath(allowed_root)
    if normalized == root or normalized.startswith(root.rstrip("/") + "/"):
        return normalized

    raise PathNotAllowedError(f"Path is outside allowed root for this host: {normalized}")
