from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional, Tuple

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from config import settings

# Opened lazily by psycopg_pool in a background thread; connections are
# established on demand, not synchronously at import time, so a
# momentarily-unavailable database does not crash process startup. Every
# call site below still fails closed - a query that can't get a
# connection raises, and callers (worker.py, api routes) treat any DB
# error as a hard failure rather than assuming success.
pool = ConnectionPool(
    conninfo=settings.database_url,
    min_size=settings.db_pool_min_size,
    max_size=settings.db_pool_max_size,
    kwargs={"row_factory": dict_row},
)

# Fixed allowlist of columns `update_scan` may write. Column NAMES are only
# ever drawn from this set (never interpolated from arbitrary caller
# input), and every VALUE is always passed as a bound parameter - no
# f-string ever carries untrusted data into SQL.
_UPDATABLE_COLUMNS = {
    "status",
    "allowed",
    "threat",
    "scanner",
    "scanner_version",
    "duration_ms",
    "error_message",
    "staging_path",
    "transfer_status",
    "scan_status_detail",
    "cleanup_status",
    "started_at",
    "completed_at",
    "sha256",
    "mime_type",
    "md5",
    "encrypted",
    "encryption_type",
    "encrypted_policy_applied",
    "needs_review",
    "aggregation_policy_applied",
    "final_policy_reason",
}


def create_scan(
    *,
    request_id: str,
    username: str,
    nextcloud_host: str,
    nextcloud_file_path: str,
    relative_path: str,
    filename: str,
    original_size: int,
    sha256: str,
    user_id: Optional[str] = None,
    email: Optional[str] = None,
    department: Optional[str] = None,
    source_application: str = "nextcloud",
    api_client_id: Optional[str] = None,
    mime_type: Optional[str] = None,
    md5: Optional[str] = None,
    original_filename: Optional[str] = None,
    extension: Optional[str] = None,
    scanner_profile_id: Optional[str] = None,
    transfer_mode: str = "ansible_fetch",
    parent_scan_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    `source_application`/`transfer_mode` default to the ORIGINAL
    single-scanner Nextcloud pipeline's values, so the existing bash-hook
    call site (api/main.py::submit_scan, unmodified) keeps working
    without passing any of the new platform fields at all. The universal
    upload API (api/routes_upload.py) passes all of them explicitly.
    """
    with pool.connection() as conn:
        row = conn.execute(
            """
            INSERT INTO scans (
                request_id, username, nextcloud_host, nextcloud_file_path,
                relative_path, filename, original_size, sha256,
                user_id, email, department, source_application, api_client_id,
                mime_type, md5, original_filename, extension,
                scanner_profile_id, transfer_mode, parent_scan_id
            ) VALUES (
                %(request_id)s, %(username)s, %(nextcloud_host)s, %(nextcloud_file_path)s,
                %(relative_path)s, %(filename)s, %(original_size)s, %(sha256)s,
                %(user_id)s, %(email)s, %(department)s, %(source_application)s, %(api_client_id)s,
                %(mime_type)s, %(md5)s, %(original_filename)s, %(extension)s,
                %(scanner_profile_id)s, %(transfer_mode)s, %(parent_scan_id)s
            )
            RETURNING *
            """,
            {
                "request_id": request_id,
                "username": username,
                "nextcloud_host": nextcloud_host,
                "nextcloud_file_path": nextcloud_file_path,
                "relative_path": relative_path,
                "filename": filename,
                "original_size": original_size,
                "sha256": sha256,
                "user_id": user_id,
                "email": email,
                "department": department,
                "source_application": source_application,
                "api_client_id": api_client_id,
                "mime_type": mime_type,
                "md5": md5,
                "original_filename": original_filename,
                "extension": extension,
                "scanner_profile_id": scanner_profile_id,
                "transfer_mode": transfer_mode,
                "parent_scan_id": parent_scan_id,
            },
        ).fetchone()
        return row


def claim_next_scan() -> Optional[Dict[str, Any]]:
    """
    Atomically claims one RECEIVED row for processing, using
    FOR UPDATE SKIP LOCKED so multiple worker processes/threads can poll
    concurrently without claiming the same row twice or blocking on each
    other (this is what makes concurrent uploads - see README Test 7 -
    safe without any external queue broker).
    """
    with pool.connection() as conn:
        row = conn.execute(
            """
            UPDATE scans
            SET status = 'VALIDATING', started_at = now()
            WHERE id = (
                SELECT id FROM scans
                WHERE status = 'RECEIVED'
                ORDER BY created_at
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            RETURNING *
            """
        ).fetchone()
        return row


def update_scan(scan_id: str, **fields: Any) -> None:
    unknown = set(fields) - _UPDATABLE_COLUMNS
    if unknown:
        raise ValueError(f"update_scan: unknown/unwritable columns: {sorted(unknown)}")
    if not fields:
        return

    set_clause = ", ".join(f"{col} = %({col})s" for col in fields)
    params: Dict[str, Any] = dict(fields)
    params["id"] = scan_id

    with pool.connection() as conn:
        conn.execute(f"UPDATE scans SET {set_clause} WHERE id = %(id)s", params)  # noqa: S608 - col names from fixed allowlist above


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    with pool.connection() as conn:
        return conn.execute("SELECT * FROM scans WHERE id = %(id)s", {"id": scan_id}).fetchone()


def list_scans(
    *,
    page: int = 1,
    page_size: int = 25,
    status: Optional[str] = None,
    username: Optional[str] = None,
    hostname: Optional[str] = None,
    date_from: Optional[datetime.datetime] = None,
    date_to: Optional[datetime.datetime] = None,
    search: Optional[str] = None,
    source: Optional[str] = None,
    antivirus: Optional[str] = None,
    sha256: Optional[str] = None,
    api_client_id: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    conditions: List[str] = []
    params: Dict[str, Any] = {}
    joins = ""

    if status:
        conditions.append("scans.status = %(status)s")
        params["status"] = status
    if username:
        conditions.append("scans.username = %(username)s")
        params["username"] = username
    if hostname:
        conditions.append("scans.nextcloud_host = %(hostname)s")
        params["hostname"] = hostname
    if date_from:
        conditions.append("scans.created_at >= %(date_from)s")
        params["date_from"] = date_from
    if date_to:
        conditions.append("scans.created_at <= %(date_to)s")
        params["date_to"] = date_to
    if search:
        conditions.append(
            "(scans.filename ILIKE %(search)s OR scans.sha256 = %(search_exact)s OR scans.request_id = %(search_exact)s OR scans.id::text = %(search_exact)s)"
        )
        params["search"] = f"%{search}%"
        params["search_exact"] = search
    if source:
        conditions.append("scans.source_application = %(source)s")
        params["source"] = source
    if sha256:
        conditions.append("scans.sha256 = %(sha256)s")
        params["sha256"] = sha256
    if api_client_id:
        conditions.append("scans.api_client_id = %(api_client_id)s")
        params["api_client_id"] = api_client_id
    if antivirus:
        joins = "JOIN scan_results ON scan_results.scan_id = scans.id"
        conditions.append("scan_results.scanner_name = %(antivirus)s")
        params["antivirus"] = antivirus

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    select_prefix = "SELECT DISTINCT scans.*" if joins else "SELECT scans.*"
    count_prefix = "SELECT count(DISTINCT scans.id) AS n" if joins else "SELECT count(*) AS n"
    page = max(page, 1)
    page_size = max(1, min(page_size, 200))
    offset = (page - 1) * page_size

    with pool.connection() as conn:
        total = conn.execute(f"{count_prefix} FROM scans {joins} {where}", params).fetchone()["n"]
        rows = conn.execute(
            f"{select_prefix} FROM scans {joins} {where} ORDER BY scans.created_at DESC LIMIT %(limit)s OFFSET %(offset)s",
            {**params, "limit": page_size, "offset": offset},
        ).fetchall()
        return rows, total


def get_dashboard_stats() -> Dict[str, Any]:
    with pool.connection() as conn:
        row = conn.execute(
            """
            SELECT
                count(*) AS total,
                count(*) FILTER (WHERE status = 'CLEAN') AS clean,
                count(*) FILTER (WHERE status = 'INFECTED') AS infected,
                count(*) FILTER (WHERE status IN ('ERROR', 'CLEANUP_FAILED')) AS errors,
                count(*) FILTER (WHERE status = 'ENCRYPTED') AS encrypted,
                count(*) FILTER (WHERE status = 'SCANNING') AS scanning,
                count(*) FILTER (WHERE status IN ('RECEIVED', 'VALIDATING', 'TRANSFERRING')) AS waiting,
                count(*) FILTER (WHERE created_at >= date_trunc('day', now())) AS uploaded_today,
                count(*) FILTER (WHERE completed_at >= date_trunc('day', now())) AS scanned_today
            FROM scans
            """
        ).fetchone()
        return row


def get_scans_over_time(days: int = 14) -> List[Dict[str, Any]]:
    with pool.connection() as conn:
        return conn.execute(
            """
            SELECT date_trunc('day', created_at)::date AS day,
                   count(*) AS total,
                   count(*) FILTER (WHERE status = 'CLEAN') AS clean,
                   count(*) FILTER (WHERE status = 'INFECTED') AS infected
            FROM scans
            WHERE created_at >= now() - (%(days)s || ' days')::interval
            GROUP BY day
            ORDER BY day
            """,
            {"days": days},
        ).fetchall()


def get_top_users(limit: int = 10) -> List[Dict[str, Any]]:
    with pool.connection() as conn:
        return conn.execute(
            """
            SELECT username,
                   count(*) AS total,
                   count(*) FILTER (WHERE status = 'CLEAN') AS clean,
                   count(*) FILTER (WHERE status = 'INFECTED') AS infected
            FROM scans
            GROUP BY username
            ORDER BY total DESC
            LIMIT %(limit)s
            """,
            {"limit": limit},
        ).fetchall()


def get_scans_by_source(limit: int = 10) -> List[Dict[str, Any]]:
    with pool.connection() as conn:
        return conn.execute(
            "SELECT source_application AS source, count(*) AS total FROM scans "
            "GROUP BY source_application ORDER BY total DESC LIMIT %(limit)s",
            {"limit": limit},
        ).fetchall()


def get_scans_by_scanner(limit: int = 10) -> List[Dict[str, Any]]:
    with pool.connection() as conn:
        return conn.execute(
            "SELECT scanner_name, count(*) AS total FROM scan_results "
            "GROUP BY scanner_name ORDER BY total DESC LIMIT %(limit)s",
            {"limit": limit},
        ).fetchall()


def get_top_threats(limit: int = 10) -> List[Dict[str, Any]]:
    with pool.connection() as conn:
        return conn.execute(
            "SELECT threat, count(*) AS total FROM scan_results "
            "WHERE status = 'INFECTED' AND threat IS NOT NULL "
            "GROUP BY threat ORDER BY total DESC LIMIT %(limit)s",
            {"limit": limit},
        ).fetchall()


# -----------------------------------------------------------------------
# scan_results - one row per scanner per scan (see api/policy.py, which
# aggregates these into the scan's final verdict).
# -----------------------------------------------------------------------

def create_scan_results(scan_id: str, results: List[Dict[str, Any]]) -> None:
    if not results:
        return
    with pool.connection() as conn:
        for r in results:
            conn.execute(
                """
                INSERT INTO scan_results (
                    scan_id, scanner_id, scanner_name, scanner_version,
                    status, threat, exit_code, duration_ms, raw_output
                ) VALUES (
                    %(scan_id)s, %(scanner_id)s, %(scanner_name)s, %(scanner_version)s,
                    %(status)s, %(threat)s, %(exit_code)s, %(duration_ms)s, %(raw_output)s
                )
                """,
                {
                    "scan_id": scan_id,
                    "scanner_id": r.get("scanner_id"),
                    "scanner_name": r.get("scanner_name"),
                    "scanner_version": r.get("scanner_version"),
                    "status": r.get("status"),
                    "threat": r.get("threat"),
                    "exit_code": r.get("exit_code"),
                    "duration_ms": r.get("duration_ms"),
                    "raw_output": r.get("message") or r.get("raw_output"),
                },
            )


def get_scan_results(scan_id: str) -> List[Dict[str, Any]]:
    with pool.connection() as conn:
        return conn.execute(
            "SELECT * FROM scan_results WHERE scan_id = %(scan_id)s ORDER BY created_at",
            {"scan_id": scan_id},
        ).fetchall()


# -----------------------------------------------------------------------
# scanners
# -----------------------------------------------------------------------

def list_scanners(enabled_only: bool = False) -> List[Dict[str, Any]]:
    where = "WHERE enabled" if enabled_only else ""
    with pool.connection() as conn:
        return conn.execute(f"SELECT * FROM scanners {where} ORDER BY name").fetchall()


def get_scanner(scanner_id: str) -> Optional[Dict[str, Any]]:
    with pool.connection() as conn:
        return conn.execute("SELECT * FROM scanners WHERE id = %(id)s", {"id": scanner_id}).fetchone()


def get_scanner_by_slug(slug: str) -> Optional[Dict[str, Any]]:
    with pool.connection() as conn:
        return conn.execute("SELECT * FROM scanners WHERE slug = %(slug)s", {"slug": slug}).fetchone()


def create_scanner(**fields: Any) -> Dict[str, Any]:
    with pool.connection() as conn:
        return conn.execute(
            """
            INSERT INTO scanners (
                name, slug, description, enabled, docker_image, scan_command,
                env_vars, result_parser, timeout_seconds, cpu_limit, memory_limit_mb
            ) VALUES (
                %(name)s, %(slug)s, %(description)s, %(enabled)s, %(docker_image)s, %(scan_command)s,
                %(env_vars)s, %(result_parser)s, %(timeout_seconds)s, %(cpu_limit)s, %(memory_limit_mb)s
            )
            RETURNING *
            """,
            {
                **fields,
                "scan_command": Jsonb(fields["scan_command"]),
                "env_vars": Jsonb(fields.get("env_vars") or {}),
            },
        ).fetchone()


def update_scanner(scanner_id: str, **fields: Any) -> None:
    if not fields:
        return
    if "scan_command" in fields:
        fields["scan_command"] = Jsonb(fields["scan_command"])
    if "env_vars" in fields:
        fields["env_vars"] = Jsonb(fields["env_vars"])
    set_clause = ", ".join(f"{col} = %({col})s" for col in fields) + ", updated_at = now()"
    with pool.connection() as conn:
        conn.execute(
            f"UPDATE scanners SET {set_clause} WHERE id = %(id)s",  # noqa: S608 - fixed known column set only
            {**fields, "id": scanner_id},
        )


def delete_scanner(scanner_id: str) -> None:
    with pool.connection() as conn:
        conn.execute("DELETE FROM scanners WHERE id = %(id)s", {"id": scanner_id})


# -----------------------------------------------------------------------
# scanner_profiles
# -----------------------------------------------------------------------

def list_profiles() -> List[Dict[str, Any]]:
    with pool.connection() as conn:
        return conn.execute(
            """
            SELECT p.*, count(ps.scanner_id) AS scanner_count
            FROM scanner_profiles p
            LEFT JOIN scanner_profile_scanners ps ON ps.profile_id = p.id
            GROUP BY p.id
            ORDER BY p.name
            """
        ).fetchall()


def get_profile(profile_id: str) -> Optional[Dict[str, Any]]:
    with pool.connection() as conn:
        return conn.execute(
            "SELECT * FROM scanner_profiles WHERE id = %(id)s", {"id": profile_id}
        ).fetchone()


def get_default_profile() -> Optional[Dict[str, Any]]:
    with pool.connection() as conn:
        return conn.execute("SELECT * FROM scanner_profiles WHERE is_default LIMIT 1").fetchone()


def create_profile(**fields: Any) -> Dict[str, Any]:
    with pool.connection() as conn:
        return conn.execute(
            """
            INSERT INTO scanner_profiles (name, slug, description, enabled, aggregation_policy)
            VALUES (%(name)s, %(slug)s, %(description)s, %(enabled)s, %(aggregation_policy)s)
            RETURNING *
            """,
            fields,
        ).fetchone()


def update_profile(profile_id: str, **fields: Any) -> None:
    if not fields:
        return
    set_clause = ", ".join(f"{col} = %({col})s" for col in fields) + ", updated_at = now()"
    with pool.connection() as conn:
        conn.execute(
            f"UPDATE scanner_profiles SET {set_clause} WHERE id = %(id)s",  # noqa: S608
            {**fields, "id": profile_id},
        )


def set_default_profile(profile_id: str) -> None:
    with pool.connection() as conn:
        conn.execute("UPDATE scanner_profiles SET is_default = false WHERE is_default")
        conn.execute(
            "UPDATE scanner_profiles SET is_default = true WHERE id = %(id)s", {"id": profile_id}
        )


def delete_profile(profile_id: str) -> None:
    with pool.connection() as conn:
        conn.execute("DELETE FROM scanner_profiles WHERE id = %(id)s", {"id": profile_id})


def set_profile_scanners(profile_id: str, scanner_ids_ordered: List[str]) -> None:
    with pool.connection() as conn:
        conn.execute(
            "DELETE FROM scanner_profile_scanners WHERE profile_id = %(profile_id)s",
            {"profile_id": profile_id},
        )
        for index, scanner_id in enumerate(scanner_ids_ordered):
            conn.execute(
                "INSERT INTO scanner_profile_scanners (profile_id, scanner_id, order_index) "
                "VALUES (%(profile_id)s, %(scanner_id)s, %(order_index)s)",
                {"profile_id": profile_id, "scanner_id": scanner_id, "order_index": index},
            )


def get_profile_scanners(profile_id: str) -> List[Dict[str, Any]]:
    """Returns the ENABLED scanners in a profile, in configured order -
    disabled scanners are silently skipped (an admin disabling a scanner
    takes effect immediately for every profile that references it,
    without needing to also edit every profile)."""
    with pool.connection() as conn:
        return conn.execute(
            """
            SELECT s.* FROM scanner_profile_scanners ps
            JOIN scanners s ON s.id = ps.scanner_id
            WHERE ps.profile_id = %(profile_id)s AND s.enabled
            ORDER BY ps.order_index
            """,
            {"profile_id": profile_id},
        ).fetchall()


# -----------------------------------------------------------------------
# api_clients
# -----------------------------------------------------------------------

def create_api_client(**fields: Any) -> Dict[str, Any]:
    with pool.connection() as conn:
        return conn.execute(
            """
            INSERT INTO api_clients (name, description, owner, enabled, key_prefix, key_hash,
                                      scanner_profile_id, permissions)
            VALUES (%(name)s, %(description)s, %(owner)s, %(enabled)s, %(key_prefix)s, %(key_hash)s,
                    %(scanner_profile_id)s, %(permissions)s)
            RETURNING *
            """,
            {**fields, "permissions": Jsonb(fields.get("permissions") or ["scan.upload", "scan.read"])},
        ).fetchone()


def get_api_client(client_id: str) -> Optional[Dict[str, Any]]:
    with pool.connection() as conn:
        return conn.execute(
            "SELECT * FROM api_clients WHERE id = %(id)s", {"id": client_id}
        ).fetchone()


def get_api_client_by_key_hash(key_hash: str) -> Optional[Dict[str, Any]]:
    with pool.connection() as conn:
        return conn.execute(
            "SELECT * FROM api_clients WHERE key_hash = %(key_hash)s "
            "AND enabled AND revoked_at IS NULL",
            {"key_hash": key_hash},
        ).fetchone()


def list_api_clients() -> List[Dict[str, Any]]:
    with pool.connection() as conn:
        return conn.execute("SELECT * FROM api_clients ORDER BY created_at DESC").fetchall()


def touch_api_client_last_used(client_id: str) -> None:
    with pool.connection() as conn:
        conn.execute(
            "UPDATE api_clients SET last_used_at = now() WHERE id = %(id)s", {"id": client_id}
        )


def revoke_api_client(client_id: str) -> None:
    with pool.connection() as conn:
        conn.execute(
            "UPDATE api_clients SET enabled = false, revoked_at = now() WHERE id = %(id)s",
            {"id": client_id},
        )


def rotate_api_client_key(client_id: str, key_prefix: str, key_hash: str) -> None:
    with pool.connection() as conn:
        conn.execute(
            "UPDATE api_clients SET key_prefix = %(key_prefix)s, key_hash = %(key_hash)s, "
            "enabled = true, revoked_at = NULL WHERE id = %(id)s",
            {"key_prefix": key_prefix, "key_hash": key_hash, "id": client_id},
        )


# -----------------------------------------------------------------------
# encrypted_file_policies
# -----------------------------------------------------------------------

def get_encrypted_policies() -> Dict[str, str]:
    with pool.connection() as conn:
        rows = conn.execute("SELECT category, policy FROM encrypted_file_policies").fetchall()
        return {r["category"]: r["policy"] for r in rows}


def set_encrypted_policy(category: str, policy: str) -> None:
    with pool.connection() as conn:
        conn.execute(
            "UPDATE encrypted_file_policies SET policy = %(policy)s, updated_at = now() "
            "WHERE category = %(category)s",
            {"policy": policy, "category": category},
        )


# -----------------------------------------------------------------------
# system_settings (singleton row)
# -----------------------------------------------------------------------

def get_system_settings() -> Dict[str, Any]:
    with pool.connection() as conn:
        row = conn.execute("SELECT settings FROM system_settings WHERE id = true").fetchone()
        return row["settings"] if row else {}


def update_system_settings(partial: Dict[str, Any]) -> None:
    with pool.connection() as conn:
        conn.execute(
            "UPDATE system_settings SET settings = settings || %(partial)s::jsonb, updated_at = now() "
            "WHERE id = true",
            {"partial": Jsonb(partial)},
        )


# -----------------------------------------------------------------------
# audit_log
# -----------------------------------------------------------------------

def record_audit(
    *,
    actor: str,
    action: str,
    object_type: Optional[str] = None,
    object_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    with pool.connection() as conn:
        conn.execute(
            """
            INSERT INTO audit_log (actor, action, object_type, object_id, ip_address, metadata)
            VALUES (%(actor)s, %(action)s, %(object_type)s, %(object_id)s, %(ip_address)s, %(metadata)s)
            """,
            {
                "actor": actor,
                "action": action,
                "object_type": object_type,
                "object_id": object_id,
                "ip_address": ip_address,
                "metadata": Jsonb(metadata or {}),
            },
        )


def list_audit_log(
    *,
    page: int = 1,
    page_size: int = 50,
    actor: Optional[str] = None,
    action: Optional[str] = None,
    object_type: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    conditions: List[str] = []
    params: Dict[str, Any] = {}
    if actor:
        conditions.append("actor = %(actor)s")
        params["actor"] = actor
    if action:
        conditions.append("action = %(action)s")
        params["action"] = action
    if object_type:
        conditions.append("object_type = %(object_type)s")
        params["object_type"] = object_type

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    page = max(page, 1)
    page_size = max(1, min(page_size, 200))
    offset = (page - 1) * page_size

    with pool.connection() as conn:
        total = conn.execute(f"SELECT count(*) AS n FROM audit_log {where}", params).fetchone()["n"]
        rows = conn.execute(
            f"SELECT * FROM audit_log {where} ORDER BY created_at DESC LIMIT %(limit)s OFFSET %(offset)s",
            {**params, "limit": page_size, "offset": offset},
        ).fetchall()
        return rows, total


def get_child_scans(scan_id: str) -> List[Dict[str, Any]]:
    """Re-scans of `scan_id` (see api/panel/routes.py::rescan) - never
    includes the original scan itself, only ones that reference it via
    parent_scan_id."""
    with pool.connection() as conn:
        return conn.execute(
            "SELECT * FROM scans WHERE parent_scan_id = %(id)s ORDER BY created_at DESC",
            {"id": scan_id},
        ).fetchall()


def find_stale_processing_scans(older_than_seconds: int) -> List[Dict[str, Any]]:
    """
    Safety net for STAGING_MAX_LIFETIME_SECONDS: finds scans that have
    been stuck in an in-progress state for longer than configured,
    typically caused by a worker crashing mid-scan. Used by the worker's
    periodic sweep to force them to ERROR and clean up any orphaned
    staging directory - never left to grow unbounded.
    """
    with pool.connection() as conn:
        return conn.execute(
            """
            SELECT * FROM scans
            WHERE status IN ('VALIDATING', 'TRANSFERRING', 'SCANNING')
              AND started_at < now() - (%(seconds)s || ' seconds')::interval
            """,
            {"seconds": older_than_seconds},
        ).fetchall()
