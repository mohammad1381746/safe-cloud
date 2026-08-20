-- =============================================================================
-- Nextcloud Upload Scanner - Platform extension (migration 2 of 2)
--
-- Turns the single-scanner (ClamAV) pipeline from 0001_init.sql into a
-- generic multi-scanner File Security Scanning Platform: pluggable
-- scanner providers, scanner profiles, per-scanner results, API key
-- management with scoped permissions, encrypted-file policy, audit log,
-- and system-wide tunable settings.
--
-- Apply on an existing database with:
--   psql "$DATABASE_URL" -f db/migrations/0002_platform.sql
-- (applied automatically alongside 0001 on a fresh container - see
-- docker-compose.yml).
-- =============================================================================

-- -----------------------------------------------------------------------------
-- New scan_status values. Each ALTER TYPE ... ADD VALUE is its own
-- statement/implicit transaction (psql's default autocommit mode) so it
-- can be used by statements later in this same file without the
-- "unsafe use of new value" restriction that applies only within a
-- single explicit transaction block.
-- -----------------------------------------------------------------------------
ALTER TYPE scan_status ADD VALUE IF NOT EXISTS 'ENCRYPTED';
ALTER TYPE scan_status ADD VALUE IF NOT EXISTS 'QUARANTINED';

-- -----------------------------------------------------------------------------
-- scanners: the pluggable scanner registry. Configuration only - see
-- api/scanners.py for the execution-side abstraction that reads these
-- rows. scan_command is a JSON ARRAY of argument-template strings
-- (Docker exec form, never a shell string) with only {{FILE}}/{{OUTPUT}}
-- placeholders permitted - validated in api/scanners.py before a row is
-- ever saved, not trusted blindly at execution time either.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scanners (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name              TEXT NOT NULL,
    slug              TEXT NOT NULL UNIQUE,
    description       TEXT,
    enabled           BOOLEAN NOT NULL DEFAULT true,
    version           TEXT,
    type              TEXT NOT NULL DEFAULT 'docker' CHECK (type IN ('docker')),

    docker_image      TEXT NOT NULL,
    scan_command      JSONB NOT NULL,              -- ["clamscan", "--no-summary", "{{FILE}}"]
    env_vars          JSONB NOT NULL DEFAULT '{}'::jsonb,
    result_parser     TEXT NOT NULL DEFAULT 'clamav_wrapper_json'
                      CHECK (result_parser IN ('clamav_wrapper_json', 'generic_exit_code')),

    timeout_seconds   INTEGER NOT NULL DEFAULT 120 CHECK (timeout_seconds > 0),
    cpu_limit         NUMERIC(4,2) NOT NULL DEFAULT 1.0 CHECK (cpu_limit > 0),
    memory_limit_mb   INTEGER NOT NULL DEFAULT 512 CHECK (memory_limit_mb > 0),

    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- scanner_profiles: named groups of scanners + how their results combine.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scanner_profiles (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                TEXT NOT NULL,
    slug                TEXT NOT NULL UNIQUE,
    description         TEXT,
    enabled             BOOLEAN NOT NULL DEFAULT true,
    aggregation_policy  TEXT NOT NULL DEFAULT 'ALL_MUST_PASS'
                        CHECK (aggregation_policy IN
                            ('ALL_MUST_PASS', 'ANY_DETECTION', 'FIRST_DETECTION', 'FIRST_SUCCESS')),
    is_default          BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scanner_profile_scanners (
    profile_id    UUID NOT NULL REFERENCES scanner_profiles(id) ON DELETE CASCADE,
    scanner_id    UUID NOT NULL REFERENCES scanners(id) ON DELETE CASCADE,
    order_index   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (profile_id, scanner_id)
);

-- Only one default profile at a time (used when an API client has none assigned).
CREATE UNIQUE INDEX IF NOT EXISTS idx_scanner_profiles_single_default
    ON scanner_profiles ((is_default)) WHERE is_default;

-- -----------------------------------------------------------------------------
-- scan_results: ONE ROW PER SCANNER PER SCAN. The final CLEAN/INFECTED/
-- ERROR verdict on `scans` is calculated FROM these by api/policy.py -
-- never stored as the only record of what happened, so a future
-- multi-engine comparison or re-aggregation never loses information.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_results (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id           UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    scanner_id        UUID REFERENCES scanners(id) ON DELETE SET NULL,
    scanner_name      TEXT NOT NULL,   -- denormalized snapshot - survives scanner deletion/rename
    scanner_version   TEXT,
    status            TEXT NOT NULL CHECK (status IN ('CLEAN', 'INFECTED', 'ERROR')),
    threat            TEXT,
    exit_code         INTEGER,
    duration_ms       INTEGER,
    raw_output        TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results (scan_id);

-- -----------------------------------------------------------------------------
-- api_clients: keys are NEVER stored in plaintext - only a SHA-256 hash
-- of the high-entropy random secret (see api/auth_apikey.py; this is the
-- standard model used by e.g. Stripe/GitHub - a fast hash is appropriate
-- here specifically because API keys, unlike passwords, are already
-- high-entropy random values, not guessable secrets a slow KDF is
-- protecting against brute force). key_prefix is stored in clear only to
-- let admins identify a key in the UI/logs without ever revealing it.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_clients (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                TEXT NOT NULL,
    description         TEXT,
    owner               TEXT,
    enabled             BOOLEAN NOT NULL DEFAULT true,

    key_prefix          TEXT NOT NULL,
    key_hash            TEXT NOT NULL UNIQUE,

    scanner_profile_id  UUID REFERENCES scanner_profiles(id) ON DELETE SET NULL,
    permissions         JSONB NOT NULL DEFAULT '["scan.upload", "scan.read"]'::jsonb,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at        TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_clients_key_hash ON api_clients (key_hash);

-- -----------------------------------------------------------------------------
-- encrypted_file_policies: one row per category, seeded below. Admin-
-- editable via /settings/encrypted-files. `default` is the fallback used
-- for any category not explicitly listed (including genuinely unknown
-- future categories).
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS encrypted_file_policies (
    category    TEXT PRIMARY KEY,
    policy      TEXT NOT NULL DEFAULT 'DENY'
                CHECK (policy IN ('ALLOW', 'DENY', 'QUARANTINE', 'MARK_FOR_REVIEW')),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO encrypted_file_policies (category, policy) VALUES
    ('archive_password_protected', 'DENY'),
    ('pdf_encrypted', 'DENY'),
    ('office_encrypted', 'DENY'),
    ('unknown_encryption', 'DENY'),
    ('default', 'DENY')
ON CONFLICT (category) DO NOTHING;

-- -----------------------------------------------------------------------------
-- audit_log: append-only. Never pruned by the retention sweep unless an
-- administrator explicitly enables it via system_settings (see
-- api/db.py::sweep_retention) - security-relevant history should not
-- silently disappear by default.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id            BIGSERIAL PRIMARY KEY,
    actor         TEXT NOT NULL,          -- admin username, or "api:<client name>", or "system"
    action        TEXT NOT NULL,
    object_type   TEXT,
    object_id     TEXT,
    ip_address    TEXT,
    metadata      JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log (actor);
CREATE INDEX IF NOT EXISTS idx_audit_log_object ON audit_log (object_type, object_id);

-- -----------------------------------------------------------------------------
-- system_settings: singleton JSONB row for runtime-tunable settings that
-- don't warrant their own table (retention days, rate limits, file
-- size/extension/MIME policies, audit-log auto-prune toggle). Seeded
-- with the .env-equivalent defaults; the admin UI (/settings/security)
-- edits this row directly rather than requiring a redeploy.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS system_settings (
    id          BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),  -- enforces exactly one row
    settings    JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO system_settings (id, settings) VALUES (true, jsonb_build_object(
    'scan_history_retention_days', 365,
    'staging_retention_hours', 24,
    'quarantine_retention_days', 30,
    'audit_log_auto_prune', false,
    'rate_limit_uploads_per_minute', 30,
    'rate_limit_requests_per_minute', 120,
    'max_concurrent_scans', 4,
    'max_file_size_bytes', 5368709120,
    'allowed_extensions', jsonb_build_array(),
    'blocked_extensions', jsonb_build_array(),
    'allowed_mime_types', jsonb_build_array(),
    'blocked_mime_types', jsonb_build_array(),
    'docs_enabled', true
)) ON CONFLICT (id) DO NOTHING;

-- -----------------------------------------------------------------------------
-- scans: extend the existing table for the platform. All nullable/
-- defaulted so the existing single-scanner Nextcloud pipeline (which
-- never sets any of these) keeps working unmodified.
-- -----------------------------------------------------------------------------
ALTER TABLE scans ADD COLUMN IF NOT EXISTS user_id            TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS email               TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS department          TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS source_application  TEXT NOT NULL DEFAULT 'nextcloud';
ALTER TABLE scans ADD COLUMN IF NOT EXISTS api_client_id       UUID REFERENCES api_clients(id) ON DELETE SET NULL;

ALTER TABLE scans ADD COLUMN IF NOT EXISTS mime_type           TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS md5                 TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS original_filename   TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS extension           TEXT;

ALTER TABLE scans ADD COLUMN IF NOT EXISTS encrypted           BOOLEAN;   -- NULL = not checked, true/false = checked
ALTER TABLE scans ADD COLUMN IF NOT EXISTS encryption_type     TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS encrypted_policy_applied TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS needs_review        BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE scans ADD COLUMN IF NOT EXISTS scanner_profile_id  UUID REFERENCES scanner_profiles(id) ON DELETE SET NULL;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS aggregation_policy_applied TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS final_policy_reason TEXT;

ALTER TABLE scans ADD COLUMN IF NOT EXISTS transfer_mode       TEXT NOT NULL DEFAULT 'ansible_fetch'
    CHECK (transfer_mode IN ('ansible_fetch', 'direct_upload'));

ALTER TABLE scans ADD COLUMN IF NOT EXISTS parent_scan_id      UUID REFERENCES scans(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_scans_api_client_id ON scans (api_client_id);
CREATE INDEX IF NOT EXISTS idx_scans_parent_scan_id ON scans (parent_scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_source_application ON scans (source_application);
CREATE INDEX IF NOT EXISTS idx_scans_sha256 ON scans (sha256);
CREATE INDEX IF NOT EXISTS idx_scans_needs_review ON scans (needs_review) WHERE needs_review;

-- -----------------------------------------------------------------------------
-- Seed the existing single-server ClamAV pipeline as the first registered
-- scanner + a "Standard" default profile, so the platform is immediately
-- usable without any admin setup, and the pre-existing Nextcloud
-- integration's scans continue to have a real `scanners`/`scanner_profiles`
-- row to reference (existing scans created before this migration are left
-- with scanner_profile_id = NULL, which api/policy.py treats as "the
-- default profile applied implicitly").
-- -----------------------------------------------------------------------------
INSERT INTO scanners (name, slug, description, docker_image, scan_command, result_parser, timeout_seconds)
VALUES (
    'ClamAV', 'clamav', 'ClamAV malware scanner (existing docker/Dockerfile image)',
    'nextcloud-scanner-clamav:latest',
    '["/usr/local/bin/scan.sh"]'::jsonb,
    'clamav_wrapper_json',
    120
) ON CONFLICT (slug) DO NOTHING;

INSERT INTO scanner_profiles (name, slug, description, aggregation_policy, is_default)
VALUES ('Standard', 'standard', 'ClamAV only - the default profile for all existing integrations', 'ALL_MUST_PASS', true)
ON CONFLICT (slug) DO NOTHING;

INSERT INTO scanner_profile_scanners (profile_id, scanner_id, order_index)
SELECT p.id, s.id, 0
FROM scanner_profiles p, scanners s
WHERE p.slug = 'standard' AND s.slug = 'clamav'
ON CONFLICT DO NOTHING;
