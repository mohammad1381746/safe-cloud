-- =============================================================================
-- Nextcloud Upload Scanner - PostgreSQL schema (migration 1 of 2)
--
-- Migration 1: the original single-scanner (ClamAV) schema. Migration 2
-- (0002_platform.sql) extends this into the multi-scanner platform -
-- scanners/profiles/api_clients/audit_log/etc - without altering
-- anything created here except a few ALTER TABLE additions on `scans`.
--
-- Both files are applied automatically on first container start by the
-- official postgres image (every *.sql file under
-- /docker-entrypoint-initdb.d/ runs once, in filename order, against an
-- empty data directory - see docker-compose.yml, which mounts the whole
-- db/migrations/ directory there). On an EXISTING database, apply by hand
-- in order:
--   psql "$DATABASE_URL" -f db/migrations/0001_init.sql
--   psql "$DATABASE_URL" -f db/migrations/0002_platform.sql
--
-- Only scan METADATA and RESULTS live here. Uploaded files themselves are
-- never stored in the database - see api/scanner.py / worker.py, which
-- delete the scanner-side staging copy after every scan regardless of
-- outcome (INFECTED source deletion is a separate, TOCTOU-checked step).
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE scan_status AS ENUM (
    'RECEIVED',
    'VALIDATING',
    'TRANSFERRING',
    'SCANNING',
    'CLEAN',
    'INFECTED',
    'ERROR',
    'CLEANUP_FAILED'
);

CREATE TABLE IF NOT EXISTS scans (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id           TEXT NOT NULL UNIQUE,

    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at           TIMESTAMPTZ,
    completed_at         TIMESTAMPTZ,

    username             TEXT NOT NULL,
    nextcloud_host       TEXT NOT NULL,
    nextcloud_file_path  TEXT NOT NULL,
    relative_path        TEXT NOT NULL,
    filename             TEXT NOT NULL,

    original_size        BIGINT NOT NULL,
    sha256                TEXT NOT NULL,

    status               scan_status NOT NULL DEFAULT 'RECEIVED',
    allowed              BOOLEAN,

    threat               TEXT,
    scanner              TEXT,
    scanner_version      TEXT,

    duration_ms          INTEGER,

    error_message        TEXT,

    staging_path         TEXT,

    -- Free-text sub-status fields (not full enums - they track independent
    -- sub-pipelines that can fail for reasons unrelated to the overall
    -- `status`, e.g. cleanup failing after a CLEAN scan already completed).
    -- Expected values: PENDING, OK, FAILED, SKIPPED, HASH_MISMATCH.
    transfer_status      TEXT NOT NULL DEFAULT 'PENDING',
    scan_status_detail   TEXT NOT NULL DEFAULT 'PENDING',
    cleanup_status       TEXT NOT NULL DEFAULT 'PENDING',

    created_by           TEXT NOT NULL DEFAULT 'nextcloud-upload-scanner.sh',

    CONSTRAINT sha256_format CHECK (sha256 ~ '^[a-f0-9]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_scans_status ON scans (status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_username ON scans (username);
CREATE INDEX IF NOT EXISTS idx_scans_nextcloud_host ON scans (nextcloud_host);
CREATE INDEX IF NOT EXISTS idx_scans_filename ON scans (filename);

-- Concurrency-safe job queue: the worker claims rows with
--   SELECT ... WHERE status = 'RECEIVED' ORDER BY created_at
--   FOR UPDATE SKIP LOCKED LIMIT 1
-- This partial index keeps that scan fast as the table grows, since only
-- unclaimed rows are ever searched this way.
CREATE INDEX IF NOT EXISTS idx_scans_queue ON scans (created_at) WHERE status = 'RECEIVED';
