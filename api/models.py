from __future__ import annotations

import re
from typing import Optional

from pydantic import BaseModel, Field, field_validator

_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


class ScanRequest(BaseModel):
    file_path: str = Field(..., min_length=1, max_length=4096)
    relative_path: str = Field(..., min_length=1, max_length=4096)
    username: str = Field(..., min_length=1, max_length=255)
    hostname: str = Field(..., min_length=1, max_length=255)
    sha256: str = Field(..., min_length=64, max_length=64)
    size: int = Field(..., ge=0)

    @field_validator("sha256")
    @classmethod
    def _validate_sha256(cls, v: str) -> str:
        if not _SHA256_RE.match(v):
            raise ValueError("sha256 must be a 64-character hex string")
        return v.lower()

    @field_validator("file_path")
    @classmethod
    def _validate_file_path_basic(cls, v: str) -> str:
        if "\x00" in v:
            raise ValueError("file_path contains a null byte")
        return v

    @field_validator("relative_path")
    @classmethod
    def _validate_relative_path(cls, v: str) -> str:
        if "\x00" in v:
            raise ValueError("relative_path contains a null byte")
        if v.startswith("/"):
            raise ValueError("relative_path must not be absolute")
        if ".." in v.split("/"):
            raise ValueError("relative_path must not contain '..'")
        return v

    @field_validator("username", "hostname")
    @classmethod
    def _validate_no_control_chars(cls, v: str) -> str:
        if "\x00" in v or "\n" in v or "\r" in v:
            raise ValueError("field contains invalid control characters")
        return v


class ScanAccepted(BaseModel):
    """202 response body for POST /api/v1/scan - the job has been queued,
    not yet processed. Poll GET /api/v1/scan/{scan_id} for the result."""

    scan_id: str
    status: str = "RECEIVED"


class ScanRejected(BaseModel):
    """Synchronous rejection - returned instead of ScanAccepted when
    request-level validation fails (bad auth, bad host, bad path, bad
    size) before any database row or background job is ever created."""

    status: str = "ERROR"
    allowed: bool = False
    message: str


class ScanStatus(BaseModel):
    """GET /api/v1/scan/{scan_id} response. Field population depends on
    `status`: CLEAN populates sha256/filename; INFECTED additionally
    populates threat; ERROR/CLEANUP_FAILED populate message; anything
    else (RECEIVED/VALIDATING/TRANSFERRING/SCANNING) is still in
    progress and only scan_id/status/allowed=None are meaningful."""

    scan_id: str
    status: str
    allowed: Optional[bool] = None
    sha256: Optional[str] = None
    filename: Optional[str] = None
    threat: Optional[str] = None
    message: Optional[str] = None
