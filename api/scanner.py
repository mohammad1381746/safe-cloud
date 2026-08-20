from __future__ import annotations

import json
import logging
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import db
import policy
from ansible_runner import AnsibleExecutionError, cleanup_run, run_playbook
from config import settings
from encryption_detect import detect_encryption
from scanners import ScannerConfig

logger = logging.getLogger("scanner.core")


def process_scan(scan: Dict[str, Any]) -> None:
    """
    Runs one scan job end to end. `scan` is a DB row already claimed by
    worker.py (status=VALIDATING, started_at set by db.claim_next_scan).

    Two transfer modes, one shared scan pipeline after that point:

      ansible_fetch  - the original Nextcloud path-reference flow.
                        ansible/fetch_from_nextcloud.yml pulls the file
                        onto this (the Scanner Server's) local staging
                        directory over SFTP.
      direct_upload  - the universal upload API
                        (api/routes_upload.py) already wrote the file's
                        bytes directly into that same staging directory -
                        nothing to fetch.

    From there both flows share: encrypted-file detection + policy,
    multi-scanner execution via the active scanner profile
    (ansible/scan_uploaded_file.yml), per-scanner result persistence, and
    policy-engine aggregation into the final verdict. Fail-closed
    throughout - every early-return path sets status=ERROR/ENCRYPTED
    with allowed=False first; the only way this function ever sets
    allowed=True is an explicit CLEAN policy decision or an explicit
    ALLOW encrypted-file policy.
    """
    scan_id = str(scan["id"])
    request_id = scan["request_id"]
    transfer_mode = scan.get("transfer_mode", "ansible_fetch")
    filename = scan["filename"]
    expected_sha256 = scan["sha256"]
    staging_dir = scan.get("staging_path") or f"{settings.staging_base.rstrip('/')}/{scan_id}"

    profile = _resolve_profile(scan)
    if profile is None:
        _fail(scan_id, "No scanner profile is configured (and no default profile exists)")
        return

    scanner_rows = db.get_profile_scanners(profile["id"])
    if not scanner_rows:
        _fail(scan_id, f"Scanner profile '{profile['name']}' has no enabled scanners")
        return
    scanner_configs = [ScannerConfig.from_row(r) for r in scanner_rows]

    db.update_scan(scan_id, status="TRANSFERRING", staging_path=staging_dir, transfer_status="PENDING")

    if transfer_mode == "ansible_fetch":
        ok, filename = _run_fetch_stage(scan, staging_dir)
        if not ok:
            return
    else:
        # direct_upload: bytes are already in staging_dir/input - written
        # synchronously by api/routes_upload.py before this row was ever
        # queued, using a hash IT computed itself (no client claim to
        # reconcile - see routes_upload.py).
        db.update_scan(scan_id, transfer_status="OK")

    # --- Encrypted-file detection + policy (both flows, after the file is confirmed local) ---
    staged_path = Path(staging_dir) / "input" / filename
    detection = detect_encryption(str(staged_path), filename) if staged_path.exists() else None

    if detection is not None:
        db.update_scan(scan_id, encrypted=detection.encrypted, encryption_type=detection.encryption_type)

        if detection.encrypted is not False:  # True (confirmed) or None (unknown) both need a policy decision
            policies = db.get_encrypted_policies()
            policy_value = policy.resolve_encrypted_policy(detection.category, policies)
            decision = policy.apply_encrypted_policy(policy_value, detection.category)
            db.update_scan(
                scan_id,
                status=decision.status,
                allowed=decision.allowed,
                needs_review=decision.needs_review,
                encrypted_policy_applied=policy_value,
                final_policy_reason=decision.reason,
                completed_at=_now(),
            )
            logger.info(_log("encrypted_policy_applied", scan_id, request_id, policy=policy_value, category=detection.category))
            if decision.quarantine:
                _quarantine_staging(scan_id, staging_dir)
            else:
                _cleanup_staging(scan_id, staging_dir, mark_status=True)
            return

    db.update_scan(scan_id, status="SCANNING")

    ok, scan_result, duration_ms = _run_scan_stage(scan, staging_dir, filename, scanner_configs)
    if not ok:
        return

    final_sha256 = scan_result.get("actual_sha256")
    if not final_sha256 or str(final_sha256).lower() != expected_sha256.lower():
        logger.warning(_log("sha256_mismatch", scan_id, request_id, expected=expected_sha256, actual=final_sha256))
        db.update_scan(scan_id, scan_status_detail="FAILED", duration_ms=duration_ms)
        _fail(scan_id, "SHA256 mismatch at scan time - refusing to trust this result")
        _cleanup_staging(scan_id, staging_dir, mark_status=True)
        return

    db.update_scan(scan_id, scan_status_detail="OK", sha256=final_sha256, duration_ms=duration_ms)

    raw_results: List[Dict[str, Any]] = scan_result.get("scan_results") or []
    outcomes = [
        policy.ScannerOutcome(
            scanner_name=r.get("scanner_name", "unknown"),
            status=r.get("status", "ERROR"),
            threat=r.get("threat"),
        )
        for r in raw_results
    ]
    decision = policy.aggregate_scan_results(outcomes, profile["aggregation_policy"])

    scanner_by_slug = {c.slug: c for c in scanner_configs}
    db.create_scan_results(scan_id, [
        {
            "scanner_id": scanner_by_slug[r["scanner_slug"]].id if r.get("scanner_slug") in scanner_by_slug else None,
            "scanner_name": r.get("scanner_name", "unknown"),
            "scanner_version": r.get("scanner_version"),
            "status": r.get("status", "ERROR"),
            "threat": r.get("threat"),
            "exit_code": None,
            "duration_ms": None,
            "message": r.get("message"),
        }
        for r in raw_results
    ])

    db.update_scan(
        scan_id,
        status=decision.status,
        allowed=decision.allowed,
        threat=decision.threat,
        scanner=", ".join(sorted({o.scanner_name for o in outcomes})),
        aggregation_policy_applied=profile["aggregation_policy"],
        final_policy_reason=decision.reason,
        completed_at=_now(),
    )
    # Include each scanner's own status/message directly in the log line -
    # not just the terse aggregate `reason` - so a human reading the log
    # can see WHY a scanner failed without a separate database query.
    # Only for non-CLEAN results, to keep the common case's log line short.
    log_kwargs: Dict[str, Any] = {"status": decision.status, "reason": decision.reason}
    if decision.status != "CLEAN":
        log_kwargs["scanner_results"] = [
            {"scanner": r.get("scanner_name", "unknown"), "status": r.get("status"),
             "threat": r.get("threat"), "message": r.get("message")}
            for r in raw_results
        ]
    logger.info(_log("scan_completed", scan_id, request_id, **log_kwargs))

    if decision.status == "INFECTED" and transfer_mode == "ansible_fetch":
        # Only the Nextcloud path-reference flow has a separate "source"
        # to delete - a direct upload's only copy IS the staging file,
        # already handled by the quarantine/cleanup call below.
        host_cfg = settings.nextcloud_hosts_map.get(scan["nextcloud_host"])
        if host_cfg is not None:
            _delete_infected_source(
                scan_id=scan_id,
                request_id=request_id,
                nextcloud_host=scan["nextcloud_host"],
                file_path=scan["nextcloud_file_path"],
                allowed_root=host_cfg.allowed_root,
                scanned_sha256=final_sha256,
            )

    if decision.status == "INFECTED":
        _cleanup_or_quarantine_infected_staging(scan_id, staging_dir)
    else:
        _cleanup_staging(scan_id, staging_dir, mark_status=True)


def force_fail_stale(scan: Dict[str, Any]) -> None:
    """Called by worker.py's periodic sweep for jobs stuck in an
    in-progress state past STAGING_MAX_LIFETIME_SECONDS - typically
    because an earlier worker process crashed mid-scan."""
    scan_id = str(scan["id"])
    request_id = scan.get("request_id", "")
    staging_dir = scan.get("staging_path") or f"{settings.staging_base.rstrip('/')}/{scan_id}"
    logger.error(_log("stale_scan_forced_error", scan_id, request_id, previous_status=scan.get("status")))
    _fail(scan_id, "Scan exceeded the configured maximum processing lifetime and was aborted")
    _cleanup_staging(scan_id, staging_dir, mark_status=True)


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------

def _resolve_profile(scan: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    profile_id = scan.get("scanner_profile_id")
    if profile_id:
        profile = db.get_profile(profile_id)
        if profile is not None:
            return profile
    return db.get_default_profile()


def _run_fetch_stage(scan: Dict[str, Any], staging_dir: str) -> tuple[bool, str]:
    """Returns (ok, filename). On failure, has already updated the DB row
    and cleaned up staging - caller should just return."""
    scan_id = str(scan["id"])
    request_id = scan["request_id"]

    host_cfg = settings.nextcloud_hosts_map.get(scan["nextcloud_host"])
    if host_cfg is None:
        db.update_scan(scan_id, transfer_status="FAILED", scan_status_detail="SKIPPED")
        _fail(scan_id, "Host is no longer in the configured allowlist")
        _cleanup_staging(scan_id, staging_dir, mark_status=True)
        return False, scan["filename"]

    fetch_run_id = f"{request_id}-fetch"
    try:
        fetch_result = run_playbook(
            run_id=fetch_run_id,
            playbook_path=settings.ansible_fetch_playbook_path,
            limit=scan["nextcloud_host"],
            extra_vars={
                "request_id": request_id,
                "nextcloud_inventory_host": scan["nextcloud_host"],
                "file_path": scan["nextcloud_file_path"],
                "expected_sha256": scan["sha256"],
                "expected_size": scan["original_size"],
                "max_file_size": settings.max_file_size,
                "allowed_root": host_cfg.allowed_root,
                "staging_dir": staging_dir,
            },
            timeout=settings.ansible_fetch_timeout,
        )
    except AnsibleExecutionError as exc:
        logger.error(_log("ansible_fetch_error", scan_id, request_id, reason=str(exc)))
        db.update_scan(scan_id, transfer_status="FAILED", scan_status_detail="SKIPPED")
        _fail(scan_id, "Scanner unavailable")
        _cleanup_staging(scan_id, staging_dir, mark_status=True)
        return False, scan["filename"]
    finally:
        cleanup_run(fetch_run_id)

    if fetch_result.get("stage") == "precondition_failed":
        db.update_scan(scan_id, transfer_status="FAILED", scan_status_detail="SKIPPED")
        _fail(scan_id, fetch_result.get("message", "Transfer failed"))
        _cleanup_staging(scan_id, staging_dir, mark_status=True)
        return False, scan["filename"]

    actual_sha256 = fetch_result.get("actual_sha256")
    if not actual_sha256 or str(actual_sha256).lower() != scan["sha256"].lower():
        logger.warning(_log("sha256_mismatch", scan_id, request_id, expected=scan["sha256"], actual=actual_sha256))
        db.update_scan(scan_id, transfer_status="OK", scan_status_detail="SKIPPED")
        _fail(scan_id, "SHA256 mismatch after transfer - refusing to trust this file")
        _cleanup_staging(scan_id, staging_dir, mark_status=True)
        return False, scan["filename"]

    db.update_scan(scan_id, transfer_status="OK")
    return True, fetch_result.get("filename", scan["filename"])


def _run_scan_stage(
    scan: Dict[str, Any], staging_dir: str, filename: str, scanner_configs: List[ScannerConfig]
) -> tuple[bool, Dict[str, Any], Optional[int]]:
    """Returns (ok, scan_result_dict, duration_ms). On failure, has
    already updated the DB row and cleaned up staging."""
    scan_id = str(scan["id"])
    request_id = scan["request_id"]

    scanners_extra_var = [
        {
            "slug": c.slug,
            "name": c.name,
            "docker_image": c.docker_image,
            "scan_command": c.scan_command,
            "env_vars": c.env_vars,
            "result_parser": c.result_parser,
            "timeout_seconds": c.timeout_seconds,
            "cpu_limit": c.cpu_limit,
            "memory_limit_mb": c.memory_limit_mb,
        }
        for c in scanner_configs
    ]

    scan_run_id = f"{request_id}-scan"
    started = time.monotonic()
    try:
        scan_result = run_playbook(
            run_id=scan_run_id,
            playbook_path=settings.ansible_scan_playbook_path,
            limit="scanner",
            extra_vars={
                "request_id": request_id,
                "staging_dir": staging_dir,
                "source_filename": filename,
                "expected_sha256": scan["sha256"],
                "scanners": scanners_extra_var,
            },
            timeout=settings.ansible_timeout,
        )
    except AnsibleExecutionError as exc:
        logger.error(_log("ansible_scan_error", scan_id, request_id, reason=str(exc)))
        db.update_scan(scan_id, scan_status_detail="FAILED")
        _fail(scan_id, "Scanner unavailable")
        _cleanup_staging(scan_id, staging_dir, mark_status=True)
        return False, {}, None
    finally:
        cleanup_run(scan_run_id)

    duration_ms = int((time.monotonic() - started) * 1000)

    if scan_result.get("stage") == "precondition_failed":
        db.update_scan(scan_id, scan_status_detail="FAILED", duration_ms=duration_ms)
        _fail(scan_id, scan_result.get("message", "Scan failed"))
        _cleanup_staging(scan_id, staging_dir, mark_status=True)
        return False, {}, duration_ms

    return True, scan_result, duration_ms


def _delete_infected_source(
    *,
    scan_id: str,
    request_id: str,
    nextcloud_host: str,
    file_path: str,
    allowed_root: str,
    scanned_sha256: str,
) -> None:
    delete_run_id = f"{request_id}-delete"
    try:
        result = run_playbook(
            run_id=delete_run_id,
            playbook_path=settings.ansible_delete_playbook_path,
            limit=nextcloud_host,
            extra_vars={
                "request_id": request_id,
                "nextcloud_inventory_host": nextcloud_host,
                "file_path": file_path,
                # The SCANNED hash, never the client's original claim -
                # this is the whole point of the TOCTOU check.
                "expected_sha256": scanned_sha256,
                "allowed_root": allowed_root,
            },
            timeout=settings.ansible_delete_timeout,
        )
    except AnsibleExecutionError as exc:
        logger.error(_log("delete_source_error", scan_id, request_id, reason=str(exc)))
        db.update_scan(scan_id, error_message=f"Source deletion failed: {exc}")
        return
    finally:
        cleanup_run(delete_run_id)

    deletion_status = result.get("deletion_status", "ABORTED")
    if deletion_status == "DELETED":
        logger.info(_log("infected_source_deleted", scan_id, request_id))
    elif deletion_status == "ALREADY_GONE":
        logger.info(_log("infected_source_already_gone", scan_id, request_id))
    else:
        logger.error(_log("infected_source_deletion_aborted", scan_id, request_id, message=result.get("message", "unknown")))
        db.update_scan(scan_id, error_message=f"Source deletion aborted: {result.get('message', 'unknown')}")


# ---------------------------------------------------------------------------
# Staging cleanup / quarantine
# ---------------------------------------------------------------------------

def _cleanup_staging(scan_id: str, staging_dir: str, *, mark_status: bool) -> None:
    path = Path(staging_dir)
    if not path.exists():
        if mark_status:
            db.update_scan(scan_id, cleanup_status="OK")
        return
    try:
        shutil.rmtree(path)
        if mark_status:
            db.update_scan(scan_id, cleanup_status="OK")
    except OSError as exc:
        logger.error(_log("cleanup_failed", scan_id, "", reason=str(exc)))
        if mark_status:
            db.update_scan(scan_id, cleanup_status="FAILED")
            _mark_cleanup_failed_if_terminal(scan_id)


def _quarantine_staging(scan_id: str, staging_dir: str) -> None:
    """Moves (never deletes) the staging directory into QUARANTINE_BASE.
    Used both for RETAIN_INFECTED_COPY=true infected results and for
    encrypted-file QUARANTINE/MARK_FOR_REVIEW policy outcomes. Never
    exposed over HTTP by the management panel."""
    source = Path(staging_dir)
    if not source.exists():
        db.update_scan(scan_id, cleanup_status="OK")
        return
    quarantine_dir = f"{settings.quarantine_base.rstrip('/')}/{scan_id}"
    try:
        Path(settings.quarantine_base).mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.move(str(source), quarantine_dir)
        Path(quarantine_dir).chmod(0o700)
        db.update_scan(scan_id, cleanup_status="OK", staging_path=quarantine_dir)
    except OSError as exc:
        logger.error(_log("quarantine_failed", scan_id, "", reason=str(exc)))
        db.update_scan(scan_id, cleanup_status="FAILED")
        _mark_cleanup_failed_if_terminal(scan_id)


def _cleanup_or_quarantine_infected_staging(scan_id: str, staging_dir: str) -> None:
    if settings.retain_infected_copy:
        _quarantine_staging(scan_id, staging_dir)
    else:
        _cleanup_staging(scan_id, staging_dir, mark_status=True)


def _mark_cleanup_failed_if_terminal(scan_id: str) -> None:
    """Overlays CLEANUP_FAILED onto an already-terminal scan without
    touching `allowed` - the scan verdict, already written by the caller
    before cleanup ran, remains the authoritative security decision."""
    current = db.get_scan(scan_id)
    if current and current["status"] in ("CLEAN", "INFECTED", "ERROR", "ENCRYPTED"):
        db.update_scan(scan_id, status="CLEANUP_FAILED")


def _fail(scan_id: str, message: str) -> None:
    db.update_scan(scan_id, status="ERROR", allowed=False, error_message=message, completed_at=_now())


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _log(event: str, scan_id: str, request_id: str, **extra: Any) -> str:
    payload: Dict[str, Any] = {"event": event, "scan_id": scan_id, "request_id": request_id}
    payload.update(extra)
    return json.dumps(payload)
