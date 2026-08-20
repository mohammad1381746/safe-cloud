from unittest.mock import patch

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)

FAKE_SYSTEM_SETTINGS = {
    "rate_limit_uploads_per_minute": 1000,
    "max_file_size_bytes": 5 * 1024 * 1024,
    "allowed_extensions": [],
    "blocked_extensions": [],
    "allowed_mime_types": [],
    "blocked_mime_types": [],
}

FULL_PERMISSIONS_CLIENT = {
    "id": "client-1",
    "name": "test-app",
    "enabled": True,
    "scanner_profile_id": None,
    "permissions": ["scan.upload", "scan.read", "scan.read_all"],
}

UPLOAD_ONLY_CLIENT = {
    "id": "client-2",
    "name": "upload-only-app",
    "enabled": True,
    "scanner_profile_id": None,
    "permissions": ["scan.upload"],
}

FAKE_SCAN_ROW = {"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "status": "RECEIVED"}


def _auth(token="sk_live_test"):
    return {"Authorization": f"Bearer {token}"}


def test_upload_requires_auth():
    resp = client.post("/api/v1/files/upload", files={"file": ("test.txt", b"hello", "text/plain")})
    assert resp.status_code == 401


def test_upload_rejects_invalid_key():
    with patch("auth_apikey.db.get_api_client_by_key_hash", return_value=None):
        resp = client.post(
            "/api/v1/files/upload",
            files={"file": ("test.txt", b"hello", "text/plain")},
            data={"username": "alice"},
            headers=_auth(),
        )
    assert resp.status_code == 401


def test_upload_missing_username_rejected():
    with patch("auth_apikey.db.get_api_client_by_key_hash", return_value=FULL_PERMISSIONS_CLIENT), \
         patch("auth_apikey.db.touch_api_client_last_used"), \
         patch("routes_upload.db.get_system_settings", return_value=FAKE_SYSTEM_SETTINGS):
        resp = client.post(
            "/api/v1/files/upload",
            files={"file": ("test.txt", b"hello", "text/plain")},
            data={"username": ""},
            headers=_auth(),
        )
    assert resp.status_code == 400


def test_upload_without_permission_rejected():
    client_no_upload = {**FULL_PERMISSIONS_CLIENT, "permissions": ["scan.read"]}
    with patch("auth_apikey.db.get_api_client_by_key_hash", return_value=client_no_upload), \
         patch("auth_apikey.db.touch_api_client_last_used"):
        resp = client.post(
            "/api/v1/files/upload",
            files={"file": ("test.txt", b"hello", "text/plain")},
            data={"username": "alice"},
            headers=_auth(),
        )
    assert resp.status_code == 403


def test_upload_success_returns_202_queued(tmp_path):
    with patch("auth_apikey.db.get_api_client_by_key_hash", return_value=FULL_PERMISSIONS_CLIENT), \
         patch("auth_apikey.db.touch_api_client_last_used"), \
         patch("routes_upload.db.get_system_settings", return_value=FAKE_SYSTEM_SETTINGS), \
         patch("routes_upload.db.list_profiles", return_value=[]), \
         patch("routes_upload.db.create_scan", return_value=FAKE_SCAN_ROW), \
         patch("routes_upload.db.update_scan"), \
         patch("routes_upload.settings.staging_base", str(tmp_path)):
        resp = client.post(
            "/api/v1/files/upload",
            files={"file": ("test.txt", b"hello world", "text/plain")},
            data={"username": "alice", "source": "my-app"},
            headers=_auth(),
        )
    assert resp.status_code == 202
    body = resp.json()
    assert body["scan_id"] == FAKE_SCAN_ROW["id"]
    assert body["status"] == "QUEUED"


def test_upload_body_larger_than_legacy_metadata_limit_is_not_blocked_by_main_middleware(tmp_path):
    # main.py's MaxBodySizeMiddleware enforces a small (16 KiB by
    # default) MAX_REQUEST_BODY_BYTES cap meant for the legacy
    # metadata-only POST /api/v1/scan endpoint. It must NOT apply that
    # cap to this endpoint - a real file upload routinely exceeds it long
    # before hitting the actual (much larger) max_file_size_bytes limit.
    # Regression test for the "Request Entity Too Large on every upload"
    # bug: this file is well over MAX_REQUEST_BODY_BYTES (16 KiB) but
    # well under FAKE_SYSTEM_SETTINGS's max_file_size_bytes (5 MiB).
    big_file = b"x" * (100 * 1024)
    with patch("auth_apikey.db.get_api_client_by_key_hash", return_value=FULL_PERMISSIONS_CLIENT), \
         patch("auth_apikey.db.touch_api_client_last_used"), \
         patch("routes_upload.db.get_system_settings", return_value=FAKE_SYSTEM_SETTINGS), \
         patch("routes_upload.db.list_profiles", return_value=[]), \
         patch("routes_upload.db.create_scan", return_value=FAKE_SCAN_ROW), \
         patch("routes_upload.db.update_scan"), \
         patch("routes_upload.settings.staging_base", str(tmp_path)):
        resp = client.post(
            "/api/v1/files/upload",
            files={"file": ("big.bin", big_file, "application/octet-stream")},
            data={"username": "alice"},
            headers=_auth(),
        )
    assert resp.status_code == 202


def test_upload_oversized_file_rejected(tmp_path):
    tiny_limit_settings = {**FAKE_SYSTEM_SETTINGS, "max_file_size_bytes": 4}
    with patch("auth_apikey.db.get_api_client_by_key_hash", return_value=FULL_PERMISSIONS_CLIENT), \
         patch("auth_apikey.db.touch_api_client_last_used"), \
         patch("routes_upload.db.get_system_settings", return_value=tiny_limit_settings), \
         patch("routes_upload.settings.staging_base", str(tmp_path)):
        resp = client.post(
            "/api/v1/files/upload",
            files={"file": ("test.txt", b"this is definitely more than four bytes", "text/plain")},
            data={"username": "alice"},
            headers=_auth(),
        )
    assert resp.status_code == 413


def test_get_scan_ownership_enforced_for_read_only_clients():
    other_clients_scan = {**FAKE_SCAN_ROW, "status": "CLEAN", "api_client_id": "someone-elses-client-id"}
    with patch("auth_apikey.db.get_api_client_by_key_hash", return_value=UPLOAD_ONLY_CLIENT), \
         patch("auth_apikey.db.touch_api_client_last_used"):
        # upload-only client also lacks scan.read entirely -> 403 first
        resp = client.get(f"/api/v1/scans/{FAKE_SCAN_ROW['id']}", headers=_auth())
    assert resp.status_code == 403


def test_get_scan_not_owned_returns_404_not_403():
    read_only_client = {**FULL_PERMISSIONS_CLIENT, "id": "client-3", "permissions": ["scan.read"]}
    other_clients_scan = {**FAKE_SCAN_ROW, "status": "CLEAN", "api_client_id": "someone-elses-client-id"}
    with patch("auth_apikey.db.get_api_client_by_key_hash", return_value=read_only_client), \
         patch("auth_apikey.db.touch_api_client_last_used"), \
         patch("routes_upload.db.get_scan", return_value=other_clients_scan):
        resp = client.get(f"/api/v1/scans/{FAKE_SCAN_ROW['id']}", headers=_auth())
    # Deliberately 404, not 403 - never confirms a scan_id exists that
    # this client doesn't own (see routes_upload.py comment).
    assert resp.status_code == 404


def test_get_scan_read_all_permission_allows_any_scan():
    other_clients_scan = {
        **FAKE_SCAN_ROW, "status": "CLEAN", "api_client_id": "someone-elses-client-id",
        "filename": "x.txt", "username": "bob", "sha256": "a" * 64, "original_size": 10,
    }
    with patch("auth_apikey.db.get_api_client_by_key_hash", return_value=FULL_PERMISSIONS_CLIENT), \
         patch("auth_apikey.db.touch_api_client_last_used"), \
         patch("routes_upload.db.get_scan", return_value=other_clients_scan), \
         patch("routes_upload.db.get_scan_results", return_value=[]):
        resp = client.get(f"/api/v1/scans/{FAKE_SCAN_ROW['id']}", headers=_auth())
    assert resp.status_code == 200


def test_scanners_public_endpoint_hides_internal_config():
    with patch("auth_apikey.db.get_api_client_by_key_hash", return_value=FULL_PERMISSIONS_CLIENT), \
         patch("auth_apikey.db.touch_api_client_last_used"), \
         patch("routes_upload.db.list_scanners", return_value=[{
             "name": "ClamAV", "slug": "clamav", "version": "1.3.0",
             "docker_image": "should-not-be-exposed", "scan_command": ["secret", "command"],
         }]):
        resp = client.get("/api/v1/scanners", headers=_auth())
    assert resp.status_code == 200
    body = resp.json()
    assert body["scanners"] == [{"name": "ClamAV", "slug": "clamav", "version": "1.3.0"}]


def test_pinned_profile_client_cannot_request_a_different_profile():
    pinned_client = {**FULL_PERMISSIONS_CLIENT, "scanner_profile_id": "profile-standard"}
    with patch("auth_apikey.db.get_api_client_by_key_hash", return_value=pinned_client), \
         patch("auth_apikey.db.touch_api_client_last_used"), \
         patch("routes_upload.db.get_system_settings", return_value=FAKE_SYSTEM_SETTINGS), \
         patch("routes_upload.db.get_profile", return_value={"id": "profile-standard", "slug": "standard"}):
        resp = client.post(
            "/api/v1/files/upload",
            files={"file": ("test.txt", b"hello", "text/plain")},
            data={"username": "alice", "profile": "high-security"},
            headers=_auth(),
        )
    assert resp.status_code == 403
