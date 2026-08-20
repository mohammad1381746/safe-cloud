"""
Sets required environment variables BEFORE any `api.*` module is imported
by a test file, since api.config.Settings() is instantiated at import time
(fail-fast on missing config). pytest loads conftest.py in a directory
before collecting sibling test modules, so this runs first.

Also puts api/ itself on sys.path: the modules under api/ import each
other with flat, sibling-style imports (e.g. `from config import
settings` in api/main.py, not `from api.config import settings`), which
only resolve if api/ is on sys.path - true when running the app from
inside api/ (uvicorn main:app / python worker.py), but not by default
when pytest imports things from the repo root.

No real PostgreSQL is required to run this suite: api/db.py's
ConnectionPool opens lazily/in the background and is never actually
queried here - every test that would touch the database patches the
specific `db.*` function it needs via unittest.mock instead.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "api"))

os.environ.setdefault("SCANNER_API_TOKEN", "test-token-abc123")
os.environ.setdefault(
    "NEXTCLOUD_HOSTS",
    '{"nextcloud01":{"ansible_host":"192.168.150.87","allowed_root":"/var/www/nextcloud/data"}}',
)
os.environ.setdefault("DATABASE_URL", "postgresql://scanner:test@localhost:5432/scanner_test")
os.environ.setdefault("ANSIBLE_RUNS_DIR", "/tmp/nextcloud-scanner-test-runs")
os.environ.setdefault("ANSIBLE_SCAN_PLAYBOOK_PATH", "/tmp/does-not-run-in-unit-tests-scan.yml")
os.environ.setdefault("ANSIBLE_DELETE_PLAYBOOK_PATH", "/tmp/does-not-run-in-unit-tests-delete.yml")
os.environ.setdefault("ANSIBLE_INVENTORY_PATH", "/tmp/does-not-run-in-unit-tests.ini")
os.environ.setdefault("MAX_FILE_SIZE", "1073741824")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "1000")
os.environ.setdefault("STAGING_BASE", "/tmp/upload-scanner-test/staging")
os.environ.setdefault("QUARANTINE_BASE", "/tmp/upload-scanner-test/quarantine")
os.environ.setdefault("PANEL_SESSION_SECRET", "test-session-secret")
os.environ.setdefault("PANEL_ADMIN_USERNAME", "admin")
# FastAPI's TestClient talks to the app over plain http://testserver (see
# starlette.testclient.TestClient's default base_url) - a Secure-flagged
# session cookie is never sent back over that, so any test that logs in
# and then makes a follow-up authenticated request would see it silently
# treated as logged-out unless this is off, exactly like a real deployment
# served over plain HTTP (see README "Troubleshooting" /
# PANEL_SESSION_COOKIE_SECURE, and the incident that motivated this line).
os.environ.setdefault("PANEL_SESSION_COOKIE_SECURE", "false")
# hash of "test-password-123", precomputed so tests don't depend on
# panel.auth.hash_password producing this exact string
os.environ.setdefault(
    "PANEL_ADMIN_PASSWORD_HASH",
    "pbkdf2_sha256$1000$aabbccddeeff00112233445566778899$"
    "5f2f9b1e2b8a6c9d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f60718293a4",
)
os.environ.setdefault("LOG_LEVEL", "WARNING")
