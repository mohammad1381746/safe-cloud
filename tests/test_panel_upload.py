import re
from unittest.mock import patch

from fastapi.testclient import TestClient

from main import app
from panel.auth import hash_password

_CSRF_RE = re.compile(rb'name="csrf_token" value="([^"]+)"')

FAKE_PROFILE = {
    "id": "33333333-3333-3333-3333-333333333333",
    "name": "Standard",
    "slug": "standard",
    "aggregation_policy": "ALL_MUST_PASS",
    "enabled": True,
    "is_default": True,
}

FAKE_SYSTEM_SETTINGS = {
    "max_file_size_bytes": 5 * 1024 * 1024,
    "allowed_extensions": [],
    "blocked_extensions": [],
    "allowed_mime_types": [],
    "blocked_mime_types": [],
}

FAKE_SCAN_ROW = {"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "status": "RECEIVED"}


def _logged_in_client() -> TestClient:
    client = TestClient(app)
    with patch("main.settings.panel_admin_password_hash", hash_password("s3cret-pass")), \
         patch("panel.auth.settings.panel_admin_password_hash", hash_password("s3cret-pass")), \
         patch("panel.auth.db.record_audit"):
        resp = client.post("/login", data={"username": "admin", "password": "s3cret-pass"}, follow_redirects=False)
        assert resp.status_code == 303
    return client


def _csrf_token(client: TestClient) -> str:
    """Pulls the real, session-bound CSRF token out of the rendered
    upload form - same double-submit round trip a real browser does -
    rather than mocking verify_csrf away, so these tests also exercise
    the CSRF plumbing itself (panel/csrf.py), not just the upload logic."""
    with patch("panel.upload.db.list_profiles", return_value=[FAKE_PROFILE]):
        resp = client.get("/upload")
    match = _CSRF_RE.search(resp.content)
    assert match, "csrf_token hidden field not found in rendered upload form"
    return match.group(1).decode()


def test_upload_form_requires_login():
    client = TestClient(app)
    resp = client.get("/upload", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


def test_upload_form_loads_when_logged_in():
    client = _logged_in_client()
    with patch("panel.upload.db.list_profiles", return_value=[FAKE_PROFILE]):
        resp = client.get("/upload")
    assert resp.status_code == 200
    assert b"Drop a file here" in resp.content


def test_upload_submit_without_file_shows_error():
    client = _logged_in_client()
    token = _csrf_token(client)
    with patch("panel.upload.db.list_profiles", return_value=[FAKE_PROFILE]):
        resp = client.post("/upload", data={"username": "alice", "csrf_token": token})
    assert resp.status_code == 400
    assert b"Choose a file" in resp.content


def test_upload_submit_missing_csrf_token_rejected():
    client = _logged_in_client()
    _csrf_token(client)  # populates the session's csrf_token, but we deliberately don't send it back
    with patch("panel.upload.db.list_profiles", return_value=[FAKE_PROFILE]):
        resp = client.post(
            "/upload",
            data={"username": "alice"},
            files={"file": ("test.txt", b"hello", "text/plain")},
        )
    assert resp.status_code == 403


def test_upload_submit_creates_scan_and_redirects(tmp_path):
    client = _logged_in_client()
    token = _csrf_token(client)
    with patch("panel.upload.db.list_profiles", return_value=[FAKE_PROFILE]), \
         patch("panel.upload.db.get_system_settings", return_value=FAKE_SYSTEM_SETTINGS), \
         patch("panel.upload.db.create_scan", return_value=FAKE_SCAN_ROW), \
         patch("panel.upload.db.update_scan"), \
         patch("panel.upload.db.record_audit") as mock_audit, \
         patch("panel.upload.settings.staging_base", str(tmp_path)):
        resp = client.post(
            "/upload",
            data={"username": "alice", "profile": "standard", "csrf_token": token},
            files={"file": ("eicar.txt", b"fake file contents", "text/plain")},
            follow_redirects=False,
        )
    assert resp.status_code == 303
    assert resp.headers["location"] == f"/scans/{FAKE_SCAN_ROW['id']}"
    mock_audit.assert_called_once()
    assert mock_audit.call_args.kwargs["action"] == "manual_upload"
    staged_file = tmp_path / FAKE_SCAN_ROW["id"] / "input" / "eicar.txt"
    assert staged_file.exists()
    assert staged_file.read_bytes() == b"fake file contents"


def test_upload_submit_oversized_rejected(tmp_path):
    client = _logged_in_client()
    token = _csrf_token(client)
    tiny_limit = {**FAKE_SYSTEM_SETTINGS, "max_file_size_bytes": 4}
    with patch("panel.upload.db.list_profiles", return_value=[FAKE_PROFILE]), \
         patch("panel.upload.db.get_system_settings", return_value=tiny_limit), \
         patch("panel.upload.settings.staging_base", str(tmp_path)):
        resp = client.post(
            "/upload",
            data={"username": "alice", "csrf_token": token},
            files={"file": ("big.bin", b"this is definitely more than four bytes", "application/octet-stream")},
        )
    assert resp.status_code == 413


def test_upload_submit_unknown_profile_rejected(tmp_path):
    client = _logged_in_client()
    token = _csrf_token(client)
    with patch("panel.upload.db.list_profiles", return_value=[FAKE_PROFILE]), \
         patch("panel.upload.settings.staging_base", str(tmp_path)):
        resp = client.post(
            "/upload",
            data={"username": "alice", "profile": "does-not-exist", "csrf_token": token},
            files={"file": ("test.txt", b"hello", "text/plain")},
        )
    assert resp.status_code == 400
    assert b"Unknown or disabled scanner profile" in resp.content


def test_upload_submit_defaults_username_to_session_user(tmp_path):
    client = _logged_in_client()
    token = _csrf_token(client)
    with patch("panel.upload.db.list_profiles", return_value=[FAKE_PROFILE]), \
         patch("panel.upload.db.get_system_settings", return_value=FAKE_SYSTEM_SETTINGS), \
         patch("panel.upload.db.create_scan", return_value=FAKE_SCAN_ROW) as mock_create, \
         patch("panel.upload.db.update_scan"), \
         patch("panel.upload.db.record_audit"), \
         patch("panel.upload.settings.staging_base", str(tmp_path)):
        resp = client.post(
            "/upload",
            data={"username": "", "csrf_token": token},
            files={"file": ("test.txt", b"hello", "text/plain")},
            follow_redirects=False,
        )
    assert resp.status_code == 303
    assert mock_create.call_args.kwargs["username"] == "admin"
