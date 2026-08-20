from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List

# =============================================================================
# Scanner provider abstraction.
#
# The core scan pipeline (api/scanner.py, ansible/scan_pipeline.yml) never
# knows anything scanner-specific - it only knows a `ScannerConfig` (loaded
# from the `scanners` DB table) and a `ScannerResult` (one row eventually
# written to `scan_results`). Adding a new antivirus is a database row via
# the admin UI (api/panel/admin_scanners.py), never a code change here.
#
# Execution itself still happens through the EXISTING Ansible/Docker
# machinery (community.docker.docker_container in scan_pipeline.yml /
# scan_uploaded_file.yml) - this module only owns CONFIGURATION and its
# validation, kept deliberately separate from EXECUTION per the project's
# security requirement: an admin can define a scanner's image/command/
# limits, but nothing here ever runs a process directly, and nothing here
# ever uses shell=True. Commands are always argument arrays (Docker's
# "exec form"), which Docker executes directly without invoking a shell
# regardless of what characters an argument contains - the strict
# character allowlist below is still enforced as defense in depth (catches
# admin mistakes, and protects against a future refactor that might
# introduce a real shell somewhere), not because exec-form is unsafe.
# =============================================================================

_PLACEHOLDER_RE = re.compile(r"\{\{(FILE|OUTPUT)\}\}")
# Allowed in a command/argument string once placeholders are stripped out:
# letters, digits, common path/flag punctuation. Deliberately excludes
# shell metacharacters (; | & ` $ ( ) > < \n) even though exec-form never
# interprets them - see module docstring.
_SAFE_ARG_RE = re.compile(r"^[A-Za-z0-9_./=:,\-+ ]*$")

_KNOWN_PARSERS = ("clamav_wrapper_json", "generic_exit_code")


class ScannerConfigError(ValueError):
    """Raised when an admin-supplied scanner configuration fails validation.
    Always raised BEFORE a scanner row is saved - never at execution time,
    so a bad config can't reach a live scan."""


@dataclass(frozen=True)
class ScannerConfig:
    id: str
    name: str
    slug: str
    enabled: bool
    docker_image: str
    scan_command: List[str]
    env_vars: Dict[str, str]
    result_parser: str
    timeout_seconds: int
    cpu_limit: float
    memory_limit_mb: int

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "ScannerConfig":
        return cls(
            id=str(row["id"]),
            name=row["name"],
            slug=row["slug"],
            enabled=row["enabled"],
            docker_image=row["docker_image"],
            scan_command=list(row["scan_command"]),
            env_vars=dict(row.get("env_vars") or {}),
            result_parser=row["result_parser"],
            timeout_seconds=row["timeout_seconds"],
            cpu_limit=float(row["cpu_limit"]),
            memory_limit_mb=row["memory_limit_mb"],
        )


@dataclass(frozen=True)
class ScannerResult:
    scanner_name: str
    scanner_version: str | None
    status: str  # CLEAN | INFECTED | ERROR
    threat: str | None
    exit_code: int | None
    duration_ms: int | None
    raw_output: str | None
    message: str | None = None


def validate_scan_command(value: Any) -> List[str]:
    """
    Validates an admin-supplied scan_command before it is ever saved to
    the `scanners` table. Must be a non-empty JSON array of non-empty
    strings, each containing only the safe-argument character set plus
    optionally the {{FILE}}/{{OUTPUT}} placeholders. Raises
    ScannerConfigError with a human-readable reason on any violation.
    """
    if not isinstance(value, list) or not value:
        raise ScannerConfigError("scan_command must be a non-empty JSON array of strings")

    if not all(isinstance(v, str) for v in value):
        raise ScannerConfigError("scan_command must contain only strings (Docker exec-form argv)")

    if len(value) > 64:
        raise ScannerConfigError("scan_command has too many arguments (max 64)")

    for arg in value:
        if len(arg) > 512:
            raise ScannerConfigError(f"scan_command argument too long (max 512 chars): {arg[:40]}...")
        stripped = _PLACEHOLDER_RE.sub("", arg)
        if not _SAFE_ARG_RE.match(stripped):
            raise ScannerConfigError(
                f"scan_command argument contains disallowed characters: {arg!r}. "
                "Only letters, digits, and ./-_=:,+ (plus {{FILE}}/{{OUTPUT}} placeholders) are permitted."
            )

    return list(value)


def validate_result_parser(value: Any) -> str:
    if value not in _KNOWN_PARSERS:
        raise ScannerConfigError(f"result_parser must be one of {_KNOWN_PARSERS}, got {value!r}")
    return value


def validate_docker_image(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScannerConfigError("docker_image is required")
    # Loose but real validation: registry/name:tag, no shell metacharacters,
    # no whitespace. Docker's own image-name grammar is more permissive
    # than this, but this project only ever needs simple `name:tag` or
    # `registry/name:tag` references.
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9./_:-]*$", value.strip()):
        raise ScannerConfigError(f"docker_image contains disallowed characters: {value!r}")
    return value.strip()


def validate_env_vars(value: Any) -> Dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ScannerConfigError("env_vars must be a JSON object of string -> string")
    result: Dict[str, str] = {}
    for k, v in value.items():
        if not isinstance(k, str) or not re.match(r"^[A-Z][A-Z0-9_]*$", k):
            raise ScannerConfigError(f"env_vars key must be an UPPER_SNAKE_CASE name: {k!r}")
        if not isinstance(v, str):
            raise ScannerConfigError(f"env_vars['{k}'] must be a string")
        result[k] = v
    return result


def render_command_preview(template: List[str], file_path: str, output_path: str) -> List[str]:
    """
    Pure-Python substitution used for admin-UI previews and unit tests.
    The AUTHORITATIVE substitution happens in Ansible (a Jinja `replace`
    filter chain in scan_pipeline.yml/scan_uploaded_file.yml, applied to
    the in-container mount paths) - this function exists so the admin can
    see what a command will look like without needing a live Ansible run,
    and so the substitution logic itself has a plain unit test.
    """
    return [
        arg.replace("{{FILE}}", file_path).replace("{{OUTPUT}}", output_path)
        for arg in template
    ]


def validate_scanner_config(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validates a full scanner form submission (admin UI / API), raising
    ScannerConfigError on the first problem found. Returns a cleaned dict
    ready to persist."""
    name = str(data.get("name", "")).strip()
    if not name:
        raise ScannerConfigError("name is required")

    slug = str(data.get("slug", "")).strip().lower()
    if not re.match(r"^[a-z0-9][a-z0-9-]{1,62}$", slug):
        raise ScannerConfigError("slug must be lowercase alphanumeric with hyphens, 2-63 chars")

    timeout_seconds = int(data.get("timeout_seconds", 120))
    if not (1 <= timeout_seconds <= 3600):
        raise ScannerConfigError("timeout_seconds must be between 1 and 3600")

    cpu_limit = float(data.get("cpu_limit", 1.0))
    if not (0.1 <= cpu_limit <= 8.0):
        raise ScannerConfigError("cpu_limit must be between 0.1 and 8.0")

    memory_limit_mb = int(data.get("memory_limit_mb", 512))
    if not (64 <= memory_limit_mb <= 16384):
        raise ScannerConfigError("memory_limit_mb must be between 64 and 16384")

    return {
        "name": name,
        "slug": slug,
        "description": str(data.get("description") or ""),
        "enabled": bool(data.get("enabled", True)),
        "docker_image": validate_docker_image(data.get("docker_image")),
        "scan_command": validate_scan_command(data.get("scan_command")),
        "env_vars": validate_env_vars(data.get("env_vars")),
        "result_parser": validate_result_parser(data.get("result_parser", "clamav_wrapper_json")),
        "timeout_seconds": timeout_seconds,
        "cpu_limit": cpu_limit,
        "memory_limit_mb": memory_limit_mb,
    }
