from pathlib import Path
from unittest.mock import patch

import pytest

import scanner as scanner_module
from ansible_runner import AnsibleExecutionError
from config import settings
from scanner import force_fail_stale, process_scan

SCAN_ROW = {
    "id": "11111111-1111-1111-1111-111111111111",
    "request_id": "req-abc123",
    "nextcloud_host": "nextcloud01",
    "nextcloud_file_path": "/var/www/nextcloud/data/admin/files/test.pdf",
    "filename": "test.pdf",
    "sha256": "a" * 64,
    "original_size": 100,
    "transfer_mode": "ansible_fetch",
    "scanner_profile_id": None,
}

FAKE_SCANNER_ROW = {
    "id": "22222222-2222-2222-2222-222222222222",
    "name": "ClamAV",
    "slug": "clamav",
    "enabled": True,
    "docker_image": "nextcloud-scanner-clamav:latest",
    "scan_command": ["/usr/local/bin/scan.sh"],
    "env_vars": {},
    "result_parser": "clamav_wrapper_json",
    "timeout_seconds": 120,
    "cpu_limit": 1.0,
    "memory_limit_mb": 512,
}

FAKE_PROFILE = {
    "id": "33333333-3333-3333-3333-333333333333",
    "name": "Standard",
    "slug": "standard",
    "aggregation_policy": "ALL_MUST_PASS",
    "enabled": True,
    "is_default": True,
}


@pytest.fixture(autouse=True)
def _isolate_staging(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "staging_base", str(tmp_path / "staging"))
    monkeypatch.setattr(settings, "quarantine_base", str(tmp_path / "quarantine"))
    monkeypatch.setattr(settings, "retain_infected_copy", False)
    yield


def _make_staging_dir(scan_id: str) -> Path:
    # Deliberately does NOT create staging_dir/input/<filename> - the
    # encrypted-file detection step in process_scan checks
    # staged_path.exists() and skips entirely when it doesn't (no real
    # file bytes are needed for these pipeline-orchestration tests).
    d = Path(settings.staging_base) / scan_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _collect_updates(mock_db):
    updates = []
    mock_db.update_scan.side_effect = lambda scan_id, **fields: updates.append(fields)
    return updates


def _configure_default_mocks(mock_db):
    """Every process_scan() call resolves a scanner profile + its
    scanners BEFORE touching Ansible at all - every test needs this."""
    mock_db.get_default_profile.return_value = FAKE_PROFILE
    mock_db.get_profile.return_value = FAKE_PROFILE
    mock_db.get_profile_scanners.return_value = [FAKE_SCANNER_ROW]
    mock_db.create_scan_results.return_value = None


def test_process_scan_clean_cleans_up_staging():
    staging_dir = _make_staging_dir(SCAN_ROW["id"])

    def fake_run_playbook(*, run_id, playbook_path, limit, extra_vars, timeout):
        if playbook_path == settings.ansible_fetch_playbook_path:
            return {"stage": "completed", "actual_sha256": SCAN_ROW["sha256"], "actual_size": 100, "filename": SCAN_ROW["filename"]}
        assert playbook_path == settings.ansible_scan_playbook_path
        return {
            "stage": "completed",
            "scan_results": [
                {"scanner_slug": "clamav", "scanner_name": "ClamAV", "status": "CLEAN", "scanner_version": "1.3.0"},
            ],
            "actual_sha256": SCAN_ROW["sha256"],
        }

    with patch("scanner.db") as mock_db, \
         patch("scanner.run_playbook", side_effect=fake_run_playbook) as mock_run, \
         patch("scanner.cleanup_run"):
        updates = _collect_updates(mock_db)
        _configure_default_mocks(mock_db)
        process_scan(SCAN_ROW)

    final = [f for f in updates if f.get("status") == "CLEAN"]
    assert final and final[0]["allowed"] is True
    assert mock_run.call_count == 2  # fetch + scan; no deletion for a clean result
    assert not staging_dir.exists()


def test_process_scan_infected_deletes_source_and_cleans_staging():
    staging_dir = _make_staging_dir(SCAN_ROW["id"])

    def fake_run_playbook(*, run_id, playbook_path, limit, extra_vars, timeout):
        if playbook_path == settings.ansible_fetch_playbook_path:
            return {"stage": "completed", "actual_sha256": SCAN_ROW["sha256"], "actual_size": 100, "filename": SCAN_ROW["filename"]}
        if playbook_path == settings.ansible_scan_playbook_path:
            return {
                "stage": "completed",
                "scan_results": [
                    {"scanner_slug": "clamav", "scanner_name": "ClamAV", "status": "INFECTED", "threat": "Eicar-Test-Signature"},
                ],
                "actual_sha256": SCAN_ROW["sha256"],
            }
        assert playbook_path == settings.ansible_delete_playbook_path
        # The deletion step must use the SCANNED hash, not (necessarily
        # different) client-claimed hash - here they're equal, but the
        # call site itself is what's being verified.
        assert extra_vars["expected_sha256"] == SCAN_ROW["sha256"]
        return {"stage": "completed", "deletion_status": "DELETED", "request_id": extra_vars["request_id"]}

    with patch("scanner.db") as mock_db, \
         patch("scanner.run_playbook", side_effect=fake_run_playbook) as mock_run, \
         patch("scanner.cleanup_run"):
        updates = _collect_updates(mock_db)
        _configure_default_mocks(mock_db)
        process_scan(SCAN_ROW)

    assert mock_run.call_count == 3  # fetch + scan + delete
    final = [f for f in updates if f.get("status") == "INFECTED"]
    assert final and final[0]["allowed"] is False and final[0]["threat"] == "Eicar-Test-Signature"
    assert not staging_dir.exists()


def test_process_scan_infected_deletion_aborted_on_hash_mismatch_does_not_change_verdict():
    _make_staging_dir(SCAN_ROW["id"])

    def fake_run_playbook(*, run_id, playbook_path, limit, extra_vars, timeout):
        if playbook_path == settings.ansible_fetch_playbook_path:
            return {"stage": "completed", "actual_sha256": SCAN_ROW["sha256"], "actual_size": 100, "filename": SCAN_ROW["filename"]}
        if playbook_path == settings.ansible_scan_playbook_path:
            return {
                "stage": "completed",
                "scan_results": [{"scanner_slug": "clamav", "scanner_name": "ClamAV", "status": "INFECTED", "threat": "Eicar-Test-Signature"}],
                "actual_sha256": SCAN_ROW["sha256"],
            }
        return {"stage": "completed", "deletion_status": "ABORTED", "message": "hash mismatch"}

    with patch("scanner.db") as mock_db, \
         patch("scanner.run_playbook", side_effect=fake_run_playbook), \
         patch("scanner.cleanup_run"):
        updates = _collect_updates(mock_db)
        _configure_default_mocks(mock_db)
        process_scan(SCAN_ROW)

    # The verdict must remain INFECTED/allowed=false even though deletion
    # was aborted - an aborted deletion is an operational concern, never
    # a reason to change the security verdict.
    final = [f for f in updates if f.get("status") == "INFECTED"]
    assert final and final[0]["allowed"] is False
    assert not any(f.get("status") == "CLEAN" for f in updates)


def test_process_scan_sha256_mismatch_at_scan_time_fails_closed():
    _make_staging_dir(SCAN_ROW["id"])

    def fake_run_playbook(*, run_id, playbook_path, limit, extra_vars, timeout):
        if playbook_path == settings.ansible_fetch_playbook_path:
            return {"stage": "completed", "actual_sha256": SCAN_ROW["sha256"], "actual_size": 100, "filename": SCAN_ROW["filename"]}
        return {
            "stage": "completed",
            "scan_results": [{"scanner_slug": "clamav", "scanner_name": "ClamAV", "status": "CLEAN"}],
            "actual_sha256": "b" * 64,  # mismatched
        }

    with patch("scanner.db") as mock_db, \
         patch("scanner.run_playbook", side_effect=fake_run_playbook) as mock_run, \
         patch("scanner.cleanup_run"):
        updates = _collect_updates(mock_db)
        _configure_default_mocks(mock_db)
        process_scan(SCAN_ROW)

    final = [f for f in updates if f.get("status") == "ERROR"]
    assert final and final[0]["allowed"] is False
    assert mock_run.call_count == 2  # fetch + scan; never trust this enough to consider deletion


def test_process_scan_sha256_mismatch_at_fetch_time_fails_closed_before_scanning():
    _make_staging_dir(SCAN_ROW["id"])

    with patch("scanner.db") as mock_db, \
         patch("scanner.run_playbook") as mock_run, \
         patch("scanner.cleanup_run"):
        updates = _collect_updates(mock_db)
        _configure_default_mocks(mock_db)
        mock_run.return_value = {"stage": "completed", "actual_sha256": "b" * 64, "actual_size": 100, "filename": SCAN_ROW["filename"]}
        process_scan(SCAN_ROW)

    final = [f for f in updates if f.get("status") == "ERROR"]
    assert final and final[0]["allowed"] is False
    assert mock_run.call_count == 1  # fetch only - scan never attempted on an unverified transfer


def test_process_scan_precondition_failed_on_nextcloud_side_marks_transfer_failed():
    _make_staging_dir(SCAN_ROW["id"])

    with patch("scanner.db") as mock_db, \
         patch("scanner.run_playbook") as mock_run, \
         patch("scanner.cleanup_run"):
        updates = _collect_updates(mock_db)
        _configure_default_mocks(mock_db)
        mock_run.return_value = {
            "stage": "precondition_failed",
            "message": "File does not exist on the Nextcloud host",
        }
        process_scan(SCAN_ROW)

    assert mock_run.call_count == 1  # fetch stage failed - scan stage never runs
    assert any(f.get("transfer_status") == "FAILED" for f in updates)
    assert any(f.get("scan_status_detail") == "SKIPPED" for f in updates)
    assert any(f.get("status") == "ERROR" and f.get("allowed") is False for f in updates)


def test_process_scan_precondition_failed_on_scanner_side_marks_scan_failed():
    _make_staging_dir(SCAN_ROW["id"])

    def fake_run_playbook(*, run_id, playbook_path, limit, extra_vars, timeout):
        if playbook_path == settings.ansible_fetch_playbook_path:
            return {"stage": "completed", "actual_sha256": SCAN_ROW["sha256"], "actual_size": 100, "filename": SCAN_ROW["filename"]}
        return {"stage": "precondition_failed", "failed_stage": "scanner", "message": "docker_container task failed"}

    with patch("scanner.db") as mock_db, \
         patch("scanner.run_playbook", side_effect=fake_run_playbook), \
         patch("scanner.cleanup_run"):
        updates = _collect_updates(mock_db)
        _configure_default_mocks(mock_db)
        process_scan(SCAN_ROW)

    assert any(f.get("transfer_status") == "OK" for f in updates)
    assert any(f.get("scan_status_detail") == "FAILED" for f in updates)
    assert any(f.get("status") == "ERROR" for f in updates)


def test_process_scan_ansible_unavailable_fails_closed_and_cleans_up():
    _make_staging_dir(SCAN_ROW["id"])

    with patch("scanner.db") as mock_db, \
         patch("scanner.run_playbook", side_effect=AnsibleExecutionError("boom")), \
         patch("scanner.cleanup_run") as mock_cleanup:
        updates = _collect_updates(mock_db)
        _configure_default_mocks(mock_db)
        process_scan(SCAN_ROW)

    assert any(f.get("status") == "ERROR" and f.get("allowed") is False for f in updates)
    mock_cleanup.assert_called_once()


def test_process_scan_no_default_profile_fails_closed():
    _make_staging_dir(SCAN_ROW["id"])

    with patch("scanner.db") as mock_db, patch("scanner.run_playbook") as mock_run:
        updates = _collect_updates(mock_db)
        mock_db.get_default_profile.return_value = None
        process_scan(SCAN_ROW)

    mock_run.assert_not_called()
    final = [f for f in updates if f.get("status") == "ERROR"]
    assert final and final[0]["allowed"] is False


def test_force_fail_stale_marks_error_and_removes_orphaned_staging():
    staging_dir = _make_staging_dir(SCAN_ROW["id"])
    row = {**SCAN_ROW, "status": "SCANNING", "staging_path": str(staging_dir)}

    with patch("scanner.db") as mock_db:
        updates = _collect_updates(mock_db)
        force_fail_stale(row)

    assert not staging_dir.exists()
    assert any(f.get("status") == "ERROR" and f.get("allowed") is False for f in updates)
