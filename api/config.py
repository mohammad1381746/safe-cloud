from __future__ import annotations

import json
import posixpath
from dataclasses import dataclass
from typing import Dict, List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


@dataclass(frozen=True)
class NextcloudHost:
    """
    One entry from NEXTCLOUD_HOSTS. `key` is what the Bash client sends as
    `hostname`, and is ALSO the exact Ansible inventory hostname used for
    `--limit` (the two are the same identifier by design - see
    security.py). `ansible_host` is informational only (shown in the
    panel / logs) - it is never used to construct the SSH connection;
    only ansible/inventory.ini's own ansible_host controls that, so a
    NEXTCLOUD_HOSTS entry whose key has no matching inventory host simply
    fails Ansible's `--limit` with a clear error rather than silently
    connecting somewhere unexpected.
    """

    key: str
    ansible_host: str
    allowed_root: str


class Settings(BaseSettings):
    """
    Central configuration, loaded from environment variables / .env.

    Settings() is instantiated once at import time (see `settings` below).
    A missing or malformed required value raises immediately at process
    startup rather than at request time - fail fast, fail closed.
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Authentication ---
    scanner_api_tokens: str = Field(..., alias="SCANNER_API_TOKEN")

    # --- Host allowlist + per-host path validation ---
    # JSON object: {"nextcloud01": {"ansible_host": "192.168.150.87", "allowed_root": "/var/www/nextcloud/data"}}
    nextcloud_hosts: str = Field(..., alias="NEXTCLOUD_HOSTS")

    # --- Database ---
    database_url: str = Field(..., alias="DATABASE_URL")
    db_pool_min_size: int = Field(1, alias="DB_POOL_MIN_SIZE")
    db_pool_max_size: int = Field(10, alias="DB_POOL_MAX_SIZE")

    # --- Ansible ---
    # Fetch (Nextcloud path-reference flow only) and scan (both flows)
    # are deliberately SEPARATE playbook runs - see
    # ansible/fetch_from_nextcloud.yml's docstring for why (it lets
    # api/scanner.py run encrypted-file detection on the file AFTER it's
    # staged locally but BEFORE any scanner container touches it, for
    # both the Nextcloud and universal-upload flows, sharing one
    # scan-only playbook instead of duplicating scan logic).
    ansible_fetch_playbook_path: str = Field(
        "/app/ansible/fetch_from_nextcloud.yml", alias="ANSIBLE_FETCH_PLAYBOOK_PATH"
    )
    ansible_scan_playbook_path: str = Field(
        "/app/ansible/scan_uploaded_file.yml", alias="ANSIBLE_SCAN_PLAYBOOK_PATH"
    )
    ansible_delete_playbook_path: str = Field(
        "/app/ansible/delete_infected_source.yml", alias="ANSIBLE_DELETE_PLAYBOOK_PATH"
    )
    ansible_inventory_path: str = Field("/app/ansible/inventory.ini", alias="ANSIBLE_INVENTORY_PATH")
    # ansible-playbook only auto-discovers ansible.cfg via a CWD-relative
    # lookup; ansible_runner.py invokes it from the worker's own working
    # directory, not from this file's directory, so the path must be
    # passed explicitly via the ANSIBLE_CONFIG env var (see ansible_runner.py).
    ansible_config_path: str = Field("/app/ansible/ansible.cfg", alias="ANSIBLE_CONFIG_PATH")
    ansible_fetch_timeout: int = Field(120, alias="ANSIBLE_FETCH_TIMEOUT")
    ansible_timeout: int = Field(120, alias="ANSIBLE_TIMEOUT")
    ansible_delete_timeout: int = Field(60, alias="ANSIBLE_DELETE_TIMEOUT")
    ansible_runs_dir: str = Field("/var/lib/nextcloud-scanner/runs", alias="ANSIBLE_RUNS_DIR")

    # --- ClamAV / Docker (all on the Scanner Server only) ---
    clamav_timeout: int = Field(120, alias="CLAMAV_TIMEOUT")
    docker_scan_image: str = Field("nextcloud-scanner-clamav:latest", alias="DOCKER_SCAN_IMAGE")

    # --- Staging / quarantine on the Scanner Server ---
    staging_base: str = Field("/var/lib/upload-scanner/staging", alias="STAGING_BASE")
    quarantine_base: str = Field("/var/lib/upload-scanner/quarantine", alias="QUARANTINE_BASE")
    retain_infected_copy: bool = Field(False, alias="RETAIN_INFECTED_COPY")
    staging_max_lifetime_seconds: int = Field(3600, alias="STAGING_MAX_LIFETIME_SECONDS")

    # --- Limits ---
    max_file_size: int = Field(5 * 1024 * 1024 * 1024, alias="MAX_FILE_SIZE")
    rate_limit_per_minute: int = Field(10, alias="RATE_LIMIT_PER_MINUTE")
    max_request_body_bytes: int = Field(16 * 1024, alias="MAX_REQUEST_BODY_BYTES")

    # --- CORS ---
    # Comma-separated origins. Empty = no cross-origin requests permitted.
    cors_allowed_origins: str = Field("", alias="CORS_ALLOWED_ORIGINS")

    # --- Worker ---
    worker_poll_interval_seconds: float = Field(2.0, alias="WORKER_POLL_INTERVAL_SECONDS")
    worker_concurrency: int = Field(2, alias="WORKER_CONCURRENCY")
    # Global cap on concurrent Ansible/Docker scan RUNS (independent of
    # WORKER_CONCURRENCY, which caps concurrent DB jobs - a single job can
    # itself launch several scanner containers via one Ansible run, so
    # this is the more precise "don't overwhelm the Docker host" limit;
    # see api/worker.py's semaphore).
    max_concurrent_scans: int = Field(4, alias="MAX_CONCURRENT_SCANS")

    # --- Bash client polling (documented here for the panel/README; the
    # Bash script itself reads its own config file, not this one) ---
    client_poll_interval_seconds: int = Field(3, alias="CLIENT_POLL_INTERVAL_SECONDS")
    client_poll_timeout_seconds: int = Field(180, alias="CLIENT_POLL_TIMEOUT_SECONDS")

    # --- Universal upload API (sync mode) ---
    sync_wait_default_timeout_seconds: int = Field(30, alias="SYNC_WAIT_DEFAULT_TIMEOUT_SECONDS")
    sync_wait_max_timeout_seconds: int = Field(120, alias="SYNC_WAIT_MAX_TIMEOUT_SECONDS")
    sync_wait_poll_interval_seconds: float = Field(0.5, alias="SYNC_WAIT_POLL_INTERVAL_SECONDS")

    # --- OpenAPI docs (FastAPI registers /docs and /redoc at startup -
    # this cannot be a runtime-editable DB setting, only an env var;
    # restart required to change it) ---
    docs_enabled: bool = Field(True, alias="DOCS_ENABLED")

    # --- Management panel ---
    panel_session_secret: str = Field(..., alias="PANEL_SESSION_SECRET")
    panel_admin_username: str = Field(..., alias="PANEL_ADMIN_USERNAME")
    # Format: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex> - see api/panel/auth.py
    panel_admin_password_hash: str = Field(..., alias="PANEL_ADMIN_PASSWORD_HASH")
    panel_session_cookie_secure: bool = Field(True, alias="PANEL_SESSION_COOKIE_SECURE")
    panel_session_max_age_seconds: int = Field(8 * 3600, alias="PANEL_SESSION_MAX_AGE_SECONDS")

    # --- Logging ---
    log_level: str = Field("INFO", alias="LOG_LEVEL")
    log_file: Optional[str] = Field(None, alias="LOG_FILE")
    # "json" (default) - one JSON object per line, for log aggregation/
    # machine parsing (unchanged default behavior). "text" - a compact,
    # human-readable single line per event, meant for reading directly in
    # a terminal (`docker compose logs -f worker`) while debugging - see
    # logging_config.py::TextFormatter.
    log_format: str = Field("json", alias="LOG_FORMAT")

    @property
    def nextcloud_hosts_map(self) -> Dict[str, NextcloudHost]:
        try:
            raw = json.loads(self.nextcloud_hosts)
        except json.JSONDecodeError as exc:
            raise ValueError(f"NEXTCLOUD_HOSTS must be valid JSON: {exc}") from exc
        if not isinstance(raw, dict) or not raw:
            raise ValueError("NEXTCLOUD_HOSTS must be a non-empty JSON object")

        result: Dict[str, NextcloudHost] = {}
        for key, entry in raw.items():
            if not isinstance(entry, dict):
                raise ValueError(f"NEXTCLOUD_HOSTS['{key}'] must be an object")
            ansible_host = str(entry.get("ansible_host", "")).strip()
            allowed_root = str(entry.get("allowed_root", "")).strip()
            if not ansible_host:
                raise ValueError(f"NEXTCLOUD_HOSTS['{key}'].ansible_host is required")
            if not allowed_root.startswith("/"):
                raise ValueError(
                    f"NEXTCLOUD_HOSTS['{key}'].allowed_root must be an absolute POSIX path"
                )
            result[str(key)] = NextcloudHost(
                key=str(key),
                ansible_host=ansible_host,
                allowed_root=posixpath.normpath(allowed_root),
            )
        return result

    @property
    def scanner_api_tokens_list(self) -> List[str]:
        tokens = [t.strip() for t in self.scanner_api_tokens.split(",") if t.strip()]
        if not tokens:
            raise ValueError("SCANNER_API_TOKEN resolved to an empty list")
        return tokens

    @property
    def cors_allowed_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]


settings = Settings()
