from unittest.mock import patch

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)

VALID_PAYLOAD = {
    "file_path": "/var/www/nextcloud/data/admin/files/test.pdf",
    "relative_path": "test.pdf",
    "username": "admin",
    "hostname": "nextcloud01",
    "sha256": "a" * 64,
    "size": 100,
}

AUTH_HEADERS = {"Authorization": "Bearer test-token-abc123"}

FAKE_ROW = {
    "id": "11111111-1111-1111-1111-111111111111",
    "status": "RECEIVED",
    "request_id": "req-abc123",
}


def test_healthz():
    resp = client.get("/healthz")
    assert resp.status_code == 200


def test_missing_token_rejected():
    resp = client.post("/api/v1/scan", json=VALID_PAYLOAD)
    assert resp.status_code == 401


def test_invalid_token_rejected():
    resp = client.post(
        "/api/v1/scan", json=VALID_PAYLOAD, headers={"Authorization": "Bearer wrong-token"}
    )
    assert resp.status_code == 401


def test_invalid_payload_returns_400():
    bad_payload = dict(VALID_PAYLOAD)
    bad_payload["sha256"] = "not-a-hash"
    resp = client.post("/api/v1/scan", json=bad_payload, headers=AUTH_HEADERS)
    assert resp.status_code == 400
    assert resp.json()["allowed"] is False


def test_valid_scan_request_returns_202_and_creates_db_row():
    with patch("main.db.create_scan", return_value=FAKE_ROW) as mock_create:
        resp = client.post("/api/v1/scan", json=VALID_PAYLOAD, headers=AUTH_HEADERS)
    assert resp.status_code == 202
    body = resp.json()
    assert body["scan_id"] == FAKE_ROW["id"]
    assert body["status"] == "RECEIVED"
    mock_create.assert_called_once()
    kwargs = mock_create.call_args.kwargs
    assert kwargs["nextcloud_host"] == "nextcloud01"
    assert kwargs["sha256"] == VALID_PAYLOAD["sha256"]


def test_unauthorized_path_returns_403_and_never_touches_db():
    payload = dict(VALID_PAYLOAD)
    payload["file_path"] = "/etc/passwd"
    with patch("main.db.create_scan") as mock_create:
        resp = client.post("/api/v1/scan", json=payload, headers=AUTH_HEADERS)
    assert resp.status_code == 403
    assert resp.json()["allowed"] is False
    mock_create.assert_not_called()


def test_unauthorized_host_returns_403_and_never_touches_db():
    payload = dict(VALID_PAYLOAD)
    payload["hostname"] = "unknown-host"
    with patch("main.db.create_scan") as mock_create:
        resp = client.post("/api/v1/scan", json=payload, headers=AUTH_HEADERS)
    assert resp.status_code == 403
    assert resp.json()["allowed"] is False
    mock_create.assert_not_called()


def test_oversized_file_returns_400_and_never_touches_db():
    payload = dict(VALID_PAYLOAD)
    payload["size"] = 10 * 1024 * 1024 * 1024
    with patch("main.db.create_scan") as mock_create:
        resp = client.post("/api/v1/scan", json=payload, headers=AUTH_HEADERS)
    assert resp.status_code == 400
    mock_create.assert_not_called()


def test_get_status_clean():
    row = {
        "id": FAKE_ROW["id"], "status": "CLEAN", "allowed": True,
        "sha256": "a" * 64, "filename": "test.pdf",
    }
    with patch("main.db.get_scan", return_value=row):
        resp = client.get(f"/api/v1/scan/{FAKE_ROW['id']}", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "CLEAN"
    assert body["allowed"] is True
    assert body["filename"] == "test.pdf"


def test_get_status_infected():
    row = {
        "id": FAKE_ROW["id"], "status": "INFECTED", "allowed": False,
        "sha256": "a" * 64, "filename": "eicar.txt", "threat": "Eicar-Test-Signature",
    }
    with patch("main.db.get_scan", return_value=row):
        resp = client.get(f"/api/v1/scan/{FAKE_ROW['id']}", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "INFECTED"
    assert body["allowed"] is False
    assert body["threat"] == "Eicar-Test-Signature"


def test_get_status_error():
    row = {
        "id": FAKE_ROW["id"], "status": "ERROR", "allowed": False,
        "error_message": "SHA256 mismatch",
    }
    with patch("main.db.get_scan", return_value=row):
        resp = client.get(f"/api/v1/scan/{FAKE_ROW['id']}", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ERROR"
    assert body["allowed"] is False
    assert body["message"] == "SHA256 mismatch"


def test_get_status_in_progress():
    row = {"id": FAKE_ROW["id"], "status": "SCANNING"}
    with patch("main.db.get_scan", return_value=row):
        resp = client.get(f"/api/v1/scan/{FAKE_ROW['id']}", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "SCANNING"
    assert body["allowed"] is None


def test_get_status_not_found():
    with patch("main.db.get_scan", return_value=None):
        resp = client.get(f"/api/v1/scan/{FAKE_ROW['id']}", headers=AUTH_HEADERS)
    assert resp.status_code == 404


def test_get_status_invalid_scan_id():
    resp = client.get("/api/v1/scan/not-a-uuid", headers=AUTH_HEADERS)
    assert resp.status_code == 400


def test_get_status_requires_auth():
    resp = client.get(f"/api/v1/scan/{FAKE_ROW['id']}")
    assert resp.status_code == 401


def test_rate_limit_enforced():
    from main import rate_limiter

    original_limit = rate_limiter.limit
    rate_limiter.limit = 1
    rate_limiter._hits.clear()
    try:
        with patch("main.db.create_scan", return_value=FAKE_ROW):
            first = client.post("/api/v1/scan", json=VALID_PAYLOAD, headers=AUTH_HEADERS)
            second = client.post("/api/v1/scan", json=VALID_PAYLOAD, headers=AUTH_HEADERS)
        assert first.status_code == 202
        assert second.status_code == 429
    finally:
        rate_limiter.limit = original_limit
        rate_limiter._hits.clear()


def test_login_page_loads():
    resp = client.get("/login")
    assert resp.status_code == 200
    assert b"Log in" in resp.content or b"log in" in resp.content.lower()


def test_dashboard_requires_login():
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


def test_scans_list_requires_login():
    resp = client.get("/scans", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


def test_login_with_correct_credentials_grants_dashboard_access():
    from panel.auth import hash_password

    with patch("main.settings.panel_admin_password_hash", hash_password("s3cret-pass")), \
         patch("panel.auth.settings.panel_admin_password_hash", hash_password("s3cret-pass")), \
         patch("panel.auth.db.record_audit"):
        resp = client.post(
            "/login",
            data={"username": "admin", "password": "s3cret-pass"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/dashboard"

        with patch("panel.routes.db.get_dashboard_stats", return_value={
            "total": 0, "clean": 0, "infected": 0, "errors": 0, "encrypted": 0,
            "scanning": 0, "waiting": 0, "uploaded_today": 0, "scanned_today": 0,
        }), patch("panel.routes.db.list_scans", return_value=([], 0)), \
             patch("panel.routes.db.get_scans_over_time", return_value=[]), \
             patch("panel.routes.db.get_top_users", return_value=[]), \
             patch("panel.routes.db.get_scans_by_source", return_value=[]), \
             patch("panel.routes.db.get_scans_by_scanner", return_value=[]), \
             patch("panel.routes.db.get_top_threats", return_value=[]):
            # follow_redirects=False (not the default True) matters here:
            # with redirects followed, an UNauthenticated request would
            # 303 to /login, which itself renders 200 - silently masking
            # a broken session and making this assertion pass either way.
            # This exact gap let PANEL_SESSION_COOKIE_SECURE default to
            # True in the test env for a long time without ever being
            # caught (see conftest.py) - assert on the real destination too.
            dash_resp = client.get("/dashboard", follow_redirects=False)
            assert dash_resp.status_code == 200
            assert b"Dashboard" in dash_resp.content


def test_login_with_wrong_password_rejected():
    with patch("panel.auth.db.record_audit"):
        resp = client.post(
            "/login",
            data={"username": "admin", "password": "totally-wrong"},
            follow_redirects=False,
        )
    assert resp.status_code == 401
