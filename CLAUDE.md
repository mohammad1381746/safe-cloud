# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

A post-upload malware scanning pipeline for Nextcloud, split across
**two servers**. A Bash hook on the Nextcloud server POSTs file metadata
(never the file itself, over that hop) to a FastAPI service on a
separate Scanner Server; the API validates and queues a job in
PostgreSQL and returns `202` immediately. A background worker on the
Scanner Server pulls the file over SFTP (Ansible `fetch`), scans it in a
hardened, ephemeral ClamAV container, and - only for a confirmed
INFECTED result, only after independently re-verifying the hash - runs a
second Ansible playbook to delete the source file back on the Nextcloud
server. The Bash hook polls `GET /api/v1/scan/{scan_id}` until it sees a
terminal status. Full design rationale, both-server install steps, and
the post-upload-vs-pre-upload distinction are in [README.md](README.md)
— read it before making architectural changes, especially section 1.

This was originally a single-server design (API and Docker on the same
box as Nextcloud); the two-server split, async job queue, PostgreSQL
history, TOCTOU-checked infected-file deletion, and management panel
were all added in one pass afterward. The single-server incident log
below (path validation, Ansible collections, tmpfs syntax, etc.) still
applies almost unchanged — the underlying Ansible/Docker mechanics
didn't change, only which host each play targets and how the API/worker
are split. Not a git repository as of this writing (no `.git/`).

**A third pass turned this into a generic "File Security Scanning
Platform"** on top of that unchanged two-server foundation: a universal
`POST /api/v1/files/upload` entry point usable by any application (not
just Nextcloud), a pluggable Antivirus/Scanner abstraction (administrators
register scanners with their own Docker image/command/limits instead of
ClamAV being hardcoded), scanner profiles with a 4-way aggregation policy,
a configurable encrypted-file policy, hashed API keys with permission
scoping, per-scanner result storage, and re-scan. The ORIGINAL Nextcloud
bash-hook entry point (`POST /api/v1/scan`) is untouched and still works
exactly as documented above and in the incident log — its
request/response shape, path validation, and polling contract are all
unchanged. Its underlying Ansible execution now runs through the SAME
`fetch_from_nextcloud.yml` + `scan_uploaded_file.yml` split described
below (the old single-file `scan_pipeline.yml` from that incident log no
longer exists on disk — see the "third pass" design-decision bullets
below for why), which is itself invisible to that entry point's callers.
Read README.md section 1a first for the legacy flow's behavior, then 1b
for the platform layer built on top of it. See "Build/verification
status" below for what's actually been verified from this third pass vs.
what's still unconfirmed against a live stack.

### Import convention inside api/ — flat, not package-relative

Every module under `api/` imports its siblings flat: `api/main.py` does
`from config import settings`, `from scanner import process_scan`, etc. —
**not** `from api.config import settings`. This means `api/` itself must
be on `sys.path` for the app to import correctly. Two places already
account for this and must stay in sync if the convention changes again:

- `api/Dockerfile` — `COPY api/ /app/` (not `/app/api`); `docker-compose.yml`'s
  `api` and `worker` services share this ONE image and differ only by
  `command:` (`uvicorn main:app ...` vs `python worker.py`) - both rely
  on `/app` (== `api/`'s contents) being the import root. Build context
  is the repo root (`context: .`), not `./api` — see the "playbook could
  not be found" incident below for why.
- `tests/conftest.py` — inserts `api/` onto `sys.path` at collection
  time, and every test file imports flat too (`from scanner import
  process_scan`, `patch("scanner.run_playbook")`, not `api.scanner...`).
  **Do not mix the two styles** — importing the same module once as
  `api.scanner` and once as flat `scanner` loads it twice under different
  names, producing two unequal classes for the same exception, so
  `except AnsibleExecutionError` silently fails to catch what a test
  raises. This exact bug happened once already; see the incident log.

## Commands

```bash
# Install Python deps (FastAPI/worker service + test tooling)
pip install -r requirements.txt

# Run the full unit test suite (mocks db.* and Ansible — no live
# PostgreSQL/Scanner/Nextcloud pair needed)
pytest tests/ -v

# Run a single test
pytest tests/test_security.py::test_path_traversal_rejected -v
pytest tests/test_scanner.py -v -k infected

# Build the ClamAV scan image (required before any real Ansible run)
docker build -t nextcloud-scanner-clamav:latest -f docker/Dockerfile docker/

# Bring up the full Scanner Server stack: api, worker, postgres, freshclam-updater
docker compose up -d --build
curl -s http://127.0.0.1:8000/healthz

# Run the legacy Nextcloud fetch+scan pipeline by hand (see README
# "Troubleshooting" for the full command with all required -e vars).
# scan_pipeline.yml no longer exists - it was split into a fetch stage
# and a scan stage, shared with the universal upload API (see below).
docker exec -it nextcloud-scanner-worker sh -c \
  'ANSIBLE_CONFIG=/app/ansible/ansible.cfg ansible-playbook -i /app/ansible/inventory.ini \
   /app/ansible/fetch_from_nextcloud.yml --limit "nextcloud01" -vvv -e @/path/to/extra_vars.json'
docker exec -it nextcloud-scanner-worker sh -c \
  'ANSIBLE_CONFIG=/app/ansible/ansible.cfg ansible-playbook -i /app/ansible/inventory.ini \
   /app/ansible/scan_uploaded_file.yml --limit "scanner" -vvv -e @/path/to/scan_extra_vars.json'

# Apply the platform-layer migration by hand against an existing database
# (fresh installs pick both migrations up automatically - see README 4.2)
docker exec -it nextcloud-scanner-postgres psql -U scanner -d scanner -f /dev/stdin < db/migrations/0002_platform.sql
```

There is no linter/formatter config in this repo; none is currently enforced.

## Architecture

```
ENTRY POINT 1 - legacy Nextcloud path-reference flow (transfer_mode=ansible_fetch):
Nextcloud Flow "Script" hook (%f %n %a)
  -> scripts/nextcloud-upload-scanner.sh    (untrusted input originates here)
  -> POST /api/v1/scan                       api/main.py -> validates, then
                                              db.create_scan(...) -> 202 + scan_id
  -> GET /api/v1/scan/{scan_id}  (polled)     api/main.py -> db.get_scan(...)

ENTRY POINT 2 - universal direct-upload API (transfer_mode=direct_upload), any app:
  -> POST /api/v1/files/upload               api/routes_upload.py -> auth_apikey verifies
                                              the API key, streams+hashes the file straight
                                              into staging/<scan_id>/input/ on the Scanner
                                              Server itself, db.create_scan(...) -> 202 (or
                                              polls internally to 200 if ?wait=true)
  -> GET /api/v1/scans/{scan_id}             api/routes_upload.py -> ownership-checked read

  both entry points converge here, on the Scanner Server:
  api/worker.py                              polls db.claim_next_scan()
                                              (FOR UPDATE SKIP LOCKED)
    -> api/scanner.py: process_scan()         orchestrates everything below
         -> resolves the scan's scanner profile (pinned client profile, explicit
            request, or system default) into an ordered List[ScannerConfig]
         -> api/ansible_runner.py             subprocess.run(["ansible-playbook", ...])

    if transfer_mode == ansible_fetch (entry point 1 only):
    -> ansible/fetch_from_nextcloud.yml        runs ON the Nextcloud host (SSH)
         realpath/stat/sha256, then ansible.builtin.fetch -> pulls the file
         onto the Scanner Server's staging dir (SFTP, over the same SSH connection)

    both entry points, once the file is staged locally:
    -> api/encryption_detect.py                best-effort local check (zipfile/pypdf/
                                                magic bytes) - if encrypted or unknown,
                                                api/policy.py::apply_encrypted_policy()
                                                decides ALLOW/DENY/QUARANTINE/MARK_FOR_REVIEW
                                                and the pipeline stops here for that file
    -> ansible/scan_uploaded_file.yml          runs ON the Scanner Server (local); re-verifies
                                                the staged file's sha256, then
                                                include_tasks: tasks/run_one_scanner.yml
                                                looped over every scanner in the resolved
                                                profile, each in its OWN hardened
                                                community.docker.docker_container
                                                (cap_drop ALL, network_mode none, own
                                                cpu/memory/timeout) -> one result per scanner
    <- api/policy.py::aggregate_scan_results()  combines all per-scanner results per the
                                                profile's aggregation_policy (ALL_MUST_PASS/
                                                ANY_DETECTION/FIRST_DETECTION/FIRST_SUCCESS)
    <- api/scanner.py persists db.create_scan_results() (one row per scanner) + the final
       aggregated CLEAN/INFECTED/ERROR/ENCRYPTED verdict on the scan row itself

    if INFECTED and transfer_mode == ansible_fetch only (never for direct uploads -
    there is no Nextcloud-side source file to delete in that case):
    -> ansible/delete_infected_source.yml     runs ON the Nextcloud host (SSH)
         re-stat + re-hash the source, compare to the SCANNED hash (not the
         client's original claim) - deletes ONLY on an exact match
```

Design decisions that aren't obvious from any single file:

- **Two-layer path validation, same pattern as before, now per-host.**
  `api/security.py::normalize_and_validate_path` is a *lexical*
  pre-filter only, checked against `NEXTCLOUD_HOSTS[host].allowed_root`
  — the worker has no filesystem access to the Nextcloud host at
  validation time (validation happens synchronously in `api/main.py`,
  before any SSH connection exists). The authoritative check
  (`realpath -e`, then a regex match against that SAME host's
  `allowed_root`, passed through as an extra-var) happens inside
  `ansible/fetch_from_nextcloud.yml`, which runs directly on the
  Nextcloud host — only relevant to the legacy path-reference entry
  point; direct uploads never send a path at all, so this check simply
  doesn't apply to that flow. A path valid for one `NEXTCLOUD_HOSTS`
  entry is rejected for every other entry - there is no global
  allowed-roots list anymore (see
  `test_security.py::test_path_valid_for_one_host_rejected_for_another`).

- **`fetch_from_nextcloud.yml` and `scan_uploaded_file.yml` are two
  separate playbook invocations now, not two plays in one file (this
  changed from the original two-server design — that older
  `scan_pipeline.yml` no longer exists).** The split exists specifically
  so `api/scanner.py::process_scan` can run Python-side encryption
  detection on the now-locally-staged file BETWEEN the two stages,
  before committing to a full multi-scanner Docker run — and so the
  scan-only stage can be shared verbatim by BOTH entry points (a direct
  upload skips the fetch stage entirely and goes straight to
  `scan_uploaded_file.yml`). Each playbook now targets exactly one
  inventory group per run (`fetch_from_nextcloud.yml` -> the specific
  Nextcloud host; `scan_uploaded_file.yml` -> `scanner`, always
  `ansible_connection=local`), so the old "`--limit` must intersect two
  plays' `hosts:` patterns at once" concern from the single-playbook
  design no longer applies — there is exactly one target group per
  `ansible-playbook` call.

- **`ansible.builtin.fetch`, not `copy`+something else, for the
  transfer.** `fetch`'s `dest` always lands on the CONTROL NODE
  regardless of `delegate_to`, and the control node here IS the Scanner
  Server (the worker process itself runs `ansible-playbook`). Combined
  with the SSH connection type, this is genuinely SFTP under the hood -
  satisfies "transfer via SSH/SFTP" without a bespoke transfer
  mechanism. Directory creation for the destination still needs an
  explicit `delegate_to: "{{ groups['scanner'][0] }}"` on the preceding
  `file` task, since `fetch` itself won't create missing parent dirs
  with the ownership/mode this project wants. Direct uploads bypass this
  entirely — `api/routes_upload.py` writes the streamed file straight
  into `staging/<scan_id>/input/` since it's already running on the
  Scanner Server; there's nothing to fetch.

- **No arbitrary Ansible extra-vars from the HTTP request, still true —
  now also true for per-scanner commands.** `api/ansible_runner.py::run_playbook`
  builds `extra_vars.json` from already-validated fields plus
  server-side config only; nothing from the raw request body is
  forwarded verbatim. `subprocess.run` always takes an argv list —
  never `shell=True`. This extends to the platform layer's scanner
  abstraction: a scanner's `scan_command` (JSON array of argument
  strings, validated by `api/scanners.py::validate_scan_command` against
  a strict allowlist regex) is only ever settable by an authenticated
  admin through the panel, never by an API-key client making an upload
  request — `{{FILE}}`/`{{OUTPUT}}` placeholders are substituted via a
  literal Jinja `replace` filter chain in
  `ansible/tasks/run_one_scanner.yml`, never re-templated or
  re-evaluated, so a filename can't smuggle in a new Jinja expression.

- **Result handoff is a file, not stdout parsing, still true.**
  `scan_uploaded_file.yml` runs locally on the Scanner Server already,
  so its `always:` block writes `final_result` directly, no
  `delegate_to: localhost` needed there (unlike
  `delete_infected_source.yml` and `fetch_from_nextcloud.yml`, which DO
  still need it, since those playbooks' single play targets the
  Nextcloud host over SSH). `run_one_scanner.yml`'s per-scanner
  `block/rescue` means one scanner's Docker failure produces an `ERROR`
  entry in the `scan_results` list rather than aborting the whole
  playbook run — the remaining scanners in the profile still execute.

- **Three-way SHA256 for the legacy fetch flow; two-way for direct
  uploads.** Legacy flow: (1) `fetch_from_nextcloud.yml` asserts the
  Nextcloud-side hash matches the client's original claim. (2)
  `scan_uploaded_file.yml` asserts the TRANSFERRED file's hash matches
  the Nextcloud-side hash (transfer-integrity check, catches SFTP
  corruption or substitution). (3) `api/scanner.py` asserts the scan
  result's `actual_sha256` still matches the client's original claim
  before trusting the CLEAN/INFECTED verdict at all. Direct-upload flow:
  the hash is computed by streaming the upload through `hashlib.sha256()`
  in `api/routes_upload.py` as it's written to disk — there's no
  separate "client claim" to compare against a second computation, since
  the API server IS what hashed the bytes, so only step (3)'s
  post-scan re-verification applies. Any mismatch anywhere in either
  chain -> `ERROR`, `allowed=false`, and (critically) no deletion is
  ever attempted based on an unverified hash.

- **`failed_stage` disambiguates WHERE something broke — simpler now
  that fetch and scan are separate playbook invocations.** All three
  playbooks share one `rescue:`-driven result shape
  (`stage: "precondition_failed"`), and `api/scanner.py` needs to know
  whether to mark the fetch stage or the scan stage as the failure. In
  the old single-file `scan_pipeline.yml` design this required computing
  `nextcloud_stage_failed` from `hostvars` across two plays in the same
  run; now each playbook only ever represents one stage, so
  `scan_uploaded_file.yml`'s rescue block just hardcodes
  `failed_stage: "scanner"` — `api/scanner.py` already knows which
  playbook it invoked (`fetch_from_nextcloud.yml` vs
  `scan_uploaded_file.yml`) from which Python function raised, so there
  is no cross-play variable lookup left to reason about.

- **TOCTOU protection is a SEPARATE playbook, invoked SEPARATELY, on
  purpose.** `ansible/delete_infected_source.yml` re-resolves the
  canonical path and re-computes the source's sha256 independently of
  everything computed during scanning, and compares against the
  ansible/`api/scanner.py`-passed `expected_sha256` = the SCANNED hash
  (`outcome["actual_sha256"]`), never the client's original claim. If
  the file changed between scan and delete, the hashes won't match and
  NOTHING is deleted (`deletion_status: "ABORTED"`) —
  `api/scanner.py::_delete_infected_source` treats an aborted deletion
  as an operational concern only; it NEVER changes the already-persisted
  INFECTED/`allowed=false` verdict. See
  `test_scanner.py::test_process_scan_infected_deletion_aborted_on_hash_mismatch_does_not_change_verdict`.

- **`api` and `worker` are deliberately different containers with
  different privileges**, sharing one image. `api` never gets the
  Docker socket or the SSH key — it only creates/reads PostgreSQL rows,
  plus (see below) writes raw staged file bytes. `worker` gets both,
  because Docker (for the scan containers) and SSH (to reach the
  Nextcloud host) both must run FROM the Scanner Server. This means a
  compromised `worker` process has effective control of the Scanner
  Server's Docker daemon — an inherent, acknowledged consequence of
  "Docker runs on the Scanner Server," not an oversight; it's why the
  more internet/upload-facing `api` process is kept separate and
  deliberately excluded from that blast radius.

- **`api` DOES touch local state in exactly one new place: the
  `staging_data` volume, shared read-write with `worker`.** This is the
  one deliberate exception to the rule above, added for the universal
  upload API — `POST /api/v1/files/upload` receives raw file bytes over
  HTTP and has to land them somewhere before a scan can happen; since
  PostgreSQL never stores file content (see README section 1b — only
  metadata/hashes are persisted), `api/routes_upload.py` streams them
  straight into `staging/<scan_id>/input/` on that shared volume. `api`
  still gets no Docker socket and no SSH key — it can create staged
  files but has no way to scan or transfer them itself; only `worker`
  (via Ansible) ever reads them back out. See `docker-compose.yml`'s
  comment on the `api` service's `volumes:` block.

- **The job queue IS PostgreSQL — no Redis/Celery/RQ.**
  `api/db.py::claim_next_scan` uses
  `SELECT ... WHERE status = 'RECEIVED' ... FOR UPDATE SKIP LOCKED LIMIT 1`
  inside an `UPDATE`, which is what makes concurrent workers/polling
  threads safe to claim from the same table without double-processing a
  row or blocking each other. `api/worker.py` polls this on a plain
  timer (`WORKER_POLL_INTERVAL_SECONDS`) with a bounded `ThreadPoolExecutor`
  (`WORKER_CONCURRENCY`) - deliberately the simplest thing that provides
  real concurrency safety, matching this project's "no huge framework"
  bias.

- **Cleanup is Python, not an Ansible `always:` block, on the Scanner
  side.** Since the worker process and the staging directory are on the
  SAME machine (`ansible_connection=local` for the `[scanner]` group),
  `api/scanner.py` just calls `shutil.rmtree` directly rather than
  routing cleanup through Ansible — simpler, and lets cleanup depend on
  `RETAIN_INFECTED_COPY` / the DB record in ways that would be awkward
  to express as static playbook logic. `_mark_cleanup_failed_if_terminal`
  overlays `CLEANUP_FAILED` onto an already-terminal row WITHOUT
  touching `allowed` — the scan verdict, once set, is never revised by a
  housekeeping failure.

- **UID/GID 10001 is a deliberate bridge for ClamAV specifically, not a
  platform-wide constant.** ClamAV's own container still runs as
  non-root uid/gid 10001 (baked into `docker/Dockerfile`), and
  `ansible/group_vars/scanner.yml` chowns the staging directories to
  that numeric GID so it can read the transferred file and write its
  result without running as root. Any NEW scanner registered through
  `/scanners` brings its own image and therefore its own UID — the
  platform doesn't assume 10001 for scanners in general; it only needs
  the registered image to be able to read a read-only bind mount and
  write to its own read-write one, whatever UID that image actually
  runs as. There is no `become` anywhere in any playbook.

- **Every scanner gets its own mount pair, not a shared one.**
  `ansible/tasks/run_one_scanner.yml` mounts `{{ input_dir }}:/scan:ro`
  (shared, read-only, safe for N scanners to read concurrently) and a
  scanner-specific `{{ output_dir }}/{{ scanner_item.slug }}:/output:rw`
  — one scanner's container can never see or corrupt another's output,
  and a scanner that crashes mid-write only ever pollutes its own
  subdirectory. This generalizes what used to be a single hardcoded
  ClamAV mount pair (`/scan/input` + `/scan/output` in the original
  single-server design, later `/scan` + `/output`) into a per-scanner
  pattern that any newly-registered scanner automatically gets for free.
  `docker/scan.sh` is ClamAV's own scan script baked into ClamAV's own
  image and referenced by its `scan_command` row in the `scanners` table
  — it has nothing to do with how OTHER registered scanners work; it's
  just the one scanner shipped by default.

- **Every scanner container is `network_mode: none`, not just
  ClamAV's.** `run_one_scanner.yml` applies this to EVERY scanner in a
  profile unconditionally — a newly-registered scanner can't opt out of
  it through the panel form (`api/scanners.py` doesn't expose a
  network-mode field at all). ClamAV's virus database specifically comes
  from the `clamav_db` named volume (mounted read-only), kept fresh by
  the separate, always-running `freshclam-updater` service in
  `docker-compose.yml`; any OTHER scanner an administrator registers
  must bring whatever signature data it needs baked into its own image
  for the same reason — there is no network path for it to fetch
  updates at scan time.

- **Settings fail fast, still true, more fields now.** `api/config.py`
  instantiates `Settings()` at import time — a missing
  `SCANNER_API_TOKEN` / `NEXTCLOUD_HOSTS` / `DATABASE_URL` /
  `PANEL_SESSION_SECRET` / `PANEL_ADMIN_USERNAME` /
  `PANEL_ADMIN_PASSWORD_HASH` crashes the process on startup. This is
  also why `tests/conftest.py` sets all of these at module scope before
  any test file's own imports run.

- **`db.py`'s `ConnectionPool` is safe to import without a live
  PostgreSQL.** `psycopg_pool.ConnectionPool` opens connections lazily/in
  a background thread rather than blocking or raising in its
  constructor — this is WHY `tests/*.py` can `import db` (transitively,
  via `main`/`scanner`) and then simply `patch("scanner.db")` /
  `patch("main.db.create_scan")` etc. without ever needing a real
  database. Don't assume this holds for every possible DB client
  library if this ever gets swapped out.

- **Rate limiting is in-process and single-instance, still true.**
  `api/main.py`'s `RateLimiter` is a sliding-window counter in a plain
  dict guarded by a `threading.Lock`. Fine since there's exactly one
  `api` replica in this design; would need a shared store before scaling
  that out horizontally.

- **`freshclam-updater` must start as a non-root user.** `freshclam` runs
  as root by default and tries to `setuid()`/`initgroups()` down to the
  `clamav` user before doing anything else. With `cap_drop: ALL`, the
  container has no `CAP_SETUID`/`CAP_SETGID`, so that drop fails with
  `initgroups() failed` before freshclam ever reaches the network. Fixed
  by adding `USER clamav` to `docker/Dockerfile.freshclam` (plus
  `chown -R clamav:clamav /var/lib/clamav /var/log/clamav` at build
  time) so the container is already unprivileged and freshclam skips the
  privilege-drop step entirely.

## Build/verification status

Built and verified in a sandboxed session without Docker, PostgreSQL, or
a real Nextcloud/Scanner host pair available.

**Single-server design (original build):** `pytest` 28/28, all YAML/shell
syntax validated. See git-less history in this file's incident log below
for the many real bugs found and fixed via live user testing after that
point (path/inventory/collections/tmpfs issues) — none of that was
caught by the sandboxed checks alone; take "tests pass" as necessary, not
sufficient.

**Two-server rewrite (this pass):**
- `pytest tests/ -v` — 46/46 passing: auth, per-host path/host
  allowlisting (including the new "path valid for one host, rejected for
  another" case), size limits, three-way SHA256 fail-closed behavior,
  the TOCTOU-abort-never-changes-verdict invariant, `failed_stage`
  transfer-vs-scan attribution, rate limiting, panel login/password
  hashing, 202+status-polling endpoints, panel auth gating — all with
  `db.*` and `ansible_runner.run_playbook` mocked.
- All YAML (`ansible/scan_pipeline.yml` — both plays,
  `ansible/delete_infected_source.yml`, `ansible/group_vars/*.yml`,
  `docker-compose.yml`) parsed successfully with `yaml.safe_load`/`safe_load_all`.
- `db/schema.sql` reviewed but not applied against a real PostgreSQL
  instance in this sandbox.
- `scripts/nextcloud-upload-scanner.sh` passes `bash -n`.
- Found and fixed one real bug this way: `Jinja2Templates.TemplateResponse`
  calls throughout `api/panel/*.py` used the deprecated
  `(name, {"request": ..., ...})` signature, which raised
  `TypeError: unhashable type: 'dict'` under the Starlette version this
  sandbox's `pip install` resolved (newer than the pinned
  `fastapi==0.115.0` in `requirements.txt`). Fixed to the modern
  `TemplateResponse(request, name, context)` form everywhere - more
  robust regardless of which Starlette version production actually ends
  up running. If you ever see that exact TypeError again, this is almost
  certainly the cause.
- **Not verified at all**: `docker build`/`docker compose up` of any
  image, a live Ansible run against a real Nextcloud+Scanner host pair,
  `ansible.builtin.fetch` actually transferring a file over real SFTP,
  the `community.docker.docker_container` task's exact argument
  acceptance against whatever `community.docker` version
  `ansible-galaxy collection install` (unpinned) resolves at build time,
  PostgreSQL schema application, the panel's actual rendered HTML/HTMX
  behavior in a browser, or ANY of the 8 end-to-end scenarios in README
  section 8.2. This is a substantially larger, unverified surface than
  any single previous incident in this log — budget real time for
  end-to-end testing before trusting this in production, and expect to
  cycle through several of the same category of bug (Ansible
  cross-play/cross-host variable access, `community.docker` argument
  format quirks, SSH/SFTP permission edge cases) that the incident log
  below already shows this project is prone to.

**Platform layer / "File Security Scanning Platform" (this pass):** same
sandbox constraints as both passes above — no Docker, no PostgreSQL, no
real Nextcloud/Scanner host pair, no browser. Verified in a fresh scratch
venv against the EXACT pinned versions in `requirements.txt` (not an
unpinned/latest set this time, since the two-server pass had already
established that gap doesn't hide real bugs on its own):
- `pytest tests/ -v` — **112/112 passing** (up from 46 in the two-server
  pass), covering everything that pass covered plus: the policy engine's
  4 aggregation policies including the deliberate `ANY_DETECTION`
  tolerates-an-error-if-another-scanner-is-clean behavior
  (`test_policy.py`), encrypted-file detection across ZIP/PDF/Office/RAR
  with a real `pypdf`-generated encrypted PDF and a hand-crafted
  encrypted ZIP that patches both the local AND central-directory header
  (`test_encryption_detect.py`), scanner command validation rejecting
  shell metacharacters and enforcing UPPER_SNAKE_CASE env var keys
  (`test_scanners_config.py`), the universal upload API's auth/permission/
  ownership/profile-pinning/oversized-file logic including a 404-not-403
  ownership-hiding check (`test_upload_api.py`), and the two-stage
  fetch/scan `process_scan()` rewrite including the new
  sha256-mismatch-at-fetch-time and no-default-profile fail-closed cases
  (`test_scanner.py`). All with `db.*` and `ansible_runner.run_playbook`
  mocked — no live database or Ansible execution.
- All YAML — `ansible/fetch_from_nextcloud.yml`,
  `ansible/scan_uploaded_file.yml`, `ansible/delete_infected_source.yml`,
  `ansible/tasks/run_one_scanner.yml`, `ansible/group_vars/*.yml`,
  `docker-compose.yml` — parsed successfully with
  `yaml.safe_load`/`safe_load_all`.
- Both `db/migrations/0001_init.sql` (9 statements) and
  `db/migrations/0002_platform.sql` (44 statements) parsed successfully
  with `sqlparse`; NOT applied against a real PostgreSQL instance.
- Every file under `api/` and `api/panel/` compiles cleanly
  (`python -m py_compile`) under Python 3.13 with the pinned dependency
  set — this only proves the files are syntactically valid and their
  top-level imports resolve, not that every code path is correct; that's
  what the 112 pytest cases are for.
- `scripts/nextcloud-upload-scanner.sh` still passes `bash -n`
  (unchanged by this pass).
- Route-wiring for the platform layer specifically was double-checked
  via `fastapi.testclient.TestClient` making real HTTP requests (not
  just introspecting `app.routes`, which is version-dependent — see the
  "false-alarm route-wiring" note below) to `/api/v1/files/upload`,
  `/api/v1/scans/{id}`, `/api/v1/scanners`, `/api/v1/profiles`, plus the
  new panel routes (`/scanners`, `/profiles`, `/settings*`, `/audit`),
  all correctly gated or responding as expected.
- **Found and fixed while building this pass** (not left for a future
  incident): the hand-crafted encrypted-ZIP test initially only flipped
  the encryption flag in the ZIP's local file header, leaving the
  central directory record (which `zipfile` actually trusts on read)
  unpatched, so the file still read back as unencrypted and the test's
  own assertion failed — fixed by patching both records. Caught by the
  test itself, not by manual inspection.
- A newer `fastapi`/`starlette` resolved via an UNPINNED `pip install`
  earlier in this session made `app.routes` / `router.routes`
  introspection show far fewer entries than expected (lazy
  `_IncludedRouter` wrappers instead of a flattened list) — this looked
  exactly like a broken `include_router()` call but wasn't; confirmed
  via `TestClient` HTTP requests against the PINNED versions instead.
  Documented here so a future session doesn't waste time chasing the
  same false alarm: **trust actual HTTP behavior via `TestClient`, never
  internal route-list introspection**, since the latter is a FastAPI/
  Starlette-version implementation detail, not a stable contract.
- **Not verified at all, on top of everything already listed as
  unverified in the two-server pass above**: any of the 10 platform
  scenarios in README section 8.3 (clean file, EICAR, multiple scanners,
  a deliberately-failing scanner, encrypted file under each policy,
  unknown-encryption RAR/7z, revoked API key, user filtering, scanner
  profile selection/pinning enforcement, re-scan) against a live stack;
  `docker exec ... python3 -c "from scanners import
  render_command_preview; ..."` and every other command in README
  section 9.1; the panel's new scanner/profile/settings CRUD forms
  actually rendering and submitting correctly in a browser (HTMX partial
  swaps, CSRF token round-tripping through a real form POST); a live
  multi-scanner `scan_uploaded_file.yml` run actually producing N
  independent `community.docker.docker_container` results and
  aggregating them correctly; whether `community.docker`'s exact
  argument acceptance still matches `ansible/tasks/run_one_scanner.yml`'s
  `tmpfs`/`volumes`/`command` usage (the two-server pass already found
  one real `tmpfs` dict-vs-list bug in this exact area — budget time to
  hit something similar here too, most likely in the per-scanner
  `cpus`/`memory`/`timeout` argument names). Treat "112/112 passing" the
  same way this file has treated every previous green test run: real
  signal on the platform's own decision logic, and zero evidence about
  whether it survives contact with actual Docker/Ansible/PostgreSQL.

> **Note on filenames in the incident log below**: these incidents refer
> to `ansible/scan_file.yml` and later `ansible/scan_pipeline.yml` —
> neither exists on disk anymore. `scan_file.yml` was renamed
> `scan_pipeline.yml` at some point between incidents (not itself
> separately logged), and `scan_pipeline.yml` was later split into
> `ansible/fetch_from_nextcloud.yml` + `ansible/scan_uploaded_file.yml`
> during the platform-layer pass (see the design-decision bullets
> above). The underlying bugs, root causes, and fixes described below
> are all still accurate history and the lessons still apply — only the
> filename you'd actually go looking for today has changed.

### Incident: `docker compose build` failed with `ansible-galaxy: not found`

After `api/*.py` was hand-edited to the flat-import convention (see
above), `docker compose up --build` failed at
`RUN pip install ... && ansible-galaxy collection install ...` with
`sh: 1: ansible-galaxy: not found`. Root causes, all fixed:

1. A new `api/requirements.txt` had been generated locally (`pip freeze`
   from `api/.venv`, judging by the file's mtime and that directory's
   presence) and was missing `ansible-core` (which provides the
   `ansible-galaxy` binary) as well as `uvicorn`. `docker-compose.yml`
   builds the `api` service with `context: ./api`, so `api/requirements.txt`
   — not the one at the repo root — is what the image actually installs
   from. Fixed by rewriting `api/requirements.txt` to match the root one
   (fastapi, uvicorn, pydantic, pydantic-settings, ansible-core,
   python-dotenv, httpx).
2. That generated `api/requirements.txt` was also UTF-16LE (a classic
   Windows PowerShell 5.1 `pip freeze > file` artifact — its `>` defaults
   to UTF-16LE, unlike `pwsh` 7+ or bash). It happened to still parse
   `pip`'s way this one time, but don't trust that; regenerate
   requirements files with `pip freeze | Out-File -Encoding utf8 file` or
   equivalent, and verify with `file <path>` if in doubt.
3. `api/` had no `.dockerignore`, so `COPY . /app` in `api/Dockerfile`
   would have baked `api/.env` (real config, including whatever token was
   in it) and the 29 MB `api/.venv` straight into the image on the next
   successful build. Added `api/.dockerignore`. The build that actually
   failed did so *before* reaching that `COPY` step, so nothing had
   leaked into an image at that point — but rotate `SCANNER_API_TOKEN` if
   an image was ever built successfully before this fix landed.
4. Fixing (1) exposed a second, unrelated bug: `api/Dockerfile` still did
   `COPY . /app/api` + `CMD ["uvicorn", "api.main:app", ...]`, which
   assumes package-relative imports — incompatible with the flat-import
   source. Fixed by changing to `COPY . /app` + `CMD ["uvicorn",
   "main:app", ...]`.
5. Fixing (4) exposed a third bug in the test suite: `tests/*.py` still
   imported everything as `api.scanner`, `api.security`, etc. Once
   `api/` was added to `sys.path` (needed for the flat imports inside
   `api/*.py` to resolve under pytest), importing both `api.scanner` *and*
   letting `api/main.py` pull in flat `scanner` loaded the same source
   file twice under two different module names — so `scanner.py`'s
   `except AnsibleExecutionError` and a test's `api.ansible_runner.AnsibleExecutionError`
   were two different classes, and 5 tests failed with the mocked
   exception propagating uncaught instead of being caught. Fixed by
   converting `tests/*.py` to the same flat-import convention (`from
   scanner import perform_scan`, `patch("scanner.run_ansible_scan")`,
   etc.) — see the "Import convention" note above. All 28 tests pass
   again after this.

### Incident: `ansible_failed`, rc=5, "Unable to create local directories(/home/scanner/.ansible/tmp)"

A live scan request through `docker compose` failed immediately (162ms,
before any real target-host connection) with `[Errno 30] Read-only file
system: b'/home/scanner/.ansible'`, surfaced to the client as a 503.

- **Cause**: `ansible-playbook` eagerly creates its local scratch
  directory (`~/.ansible/tmp`, controlled by the `local_tmp` config) at
  startup, before touching any inventory host. The `api` service in
  `docker-compose.yml` runs with `read_only: true` and `HOME=/home/scanner`
  (set in `api/Dockerfile`), and only `/tmp` is writable (tmpfs). Same
  root cause would also hit `~/.ansible/cp` (the SSH ControlMaster socket
  dir) on the very next attempt to actually connect to a target host, and
  would *also* affect the systemd/bare-metal deployment, since
  `systemd/scanner-api.service` sets `ProtectHome=true` (hides
  `/home/scanner` entirely) — only `PrivateTmp=true`'s private `/tmp` is
  writable there too.
- **Fix**: added `local_tmp = /tmp/ansible-local` (`[defaults]`) and
  `control_path_dir = /tmp/ansible-cp` (`[ssh_connection]`) to
  `ansible/ansible.cfg`, redirecting both to the one path that's writable
  under every deployment mode.
- **A second bug this exposed**: `ansible/ansible.cfg` was never actually
  being read. `ansible-playbook` only auto-discovers `ansible.cfg` via a
  CWD-relative lookup, but `api/ansible_runner.py`'s `subprocess.run` call
  didn't set `cwd`, so it ran from the API's own working directory
  (`/app`), not `/app/ansible`. Fixed by adding a dedicated
  `ANSIBLE_CONFIG_PATH` setting (`api/config.py`, default
  `/app/ansible/ansible.cfg`) and passing it via `env["ANSIBLE_CONFIG"]`
  on the subprocess call in `api/ansible_runner.py`, rather than relying
  on cwd-based discovery. If you ever see Ansible behaving as if
  `ansible.cfg` doesn't exist, check this env var is actually reaching
  the subprocess first — everything else in that file (`host_key_checking`,
  `retry_files_enabled`, etc.) silently no-ops if it isn't.
- Bare-metal deployments must also override `ANSIBLE_CONFIG_PATH` (along
  with `ANSIBLE_PLAYBOOK_PATH`/`ANSIBLE_INVENTORY_PATH`) to point at
  `/opt/nextcloud-upload-scanner/ansible/...` — README section 4.2 now
  does this with a `sed` step against the copied `.env`.

### Incident: `ERROR! the playbook: /app/ansible/scan_file.yml could not be found`

Next request after the two fixes above still failed, this time much
earlier and more plainly: Ansible itself couldn't locate the playbook
file inside the `api` container at all.

- **Cause**: `ansible/` was supplied to the `api` container purely via a
  runtime bind mount (`./ansible:/app/ansible:ro` in `docker-compose.yml`,
  with nothing baked into the image — the `api` service built with
  `context: ./api`, which can't even see the sibling `ansible/` directory
  at build time). The mount not showing up inside the container could not
  be verified directly in this sandbox (no Docker available here), but a
  directory bind mount whose host source is briefly inaccessible commonly
  presents as a silently empty directory rather than a hard failure at
  `docker compose up` — this is a known rough edge with bind-mounting
  paths outside a container's build context, and is more likely to bite
  on Windows/Docker Desktop than on native Linux.
- **Fix, structural rather than a workaround**: `ansible/scan_file.yml`,
  `ansible.cfg`, and `group_vars/` are now baked into the `api` image at
  build time. `docker-compose.yml`'s `api` service builds with
  `context: .` / `dockerfile: api/Dockerfile` (repo root, not `./api`
  anymore), and `api/Dockerfile` does `COPY ansible/ /app/ansible/`
  alongside `COPY api/ /app/`. The runtime bind mount for the whole
  directory was removed entirely — a stale/misconfigured mount should
  never again be able to shadow a working image with an empty directory.
  `ansible/inventory.ini` is baked in too as a working default, but is
  the one piece meant to change without a rebuild (adding/removing
  target hosts), so it stays independently overridable via a **single-file**
  bind mount (commented out by default in `docker-compose.yml`) —
  single-file mounts fail loudly if the host path is missing, unlike a
  directory mount, which is exactly why the directory-mount approach was
  abandoned here.
- **Consequence for future edits**: because `ansible/scan_file.yml` etc.
  are now baked in, editing them requires `docker compose up -d --build api`
  to take effect — a plain `docker compose restart` will keep serving the
  old copy from the existing image layer. This is a real behavior change
  from before; don't assume playbook edits are picked up live.
- Root-level `.dockerignore` was added (build context moved to repo
  root), replacing the now-removed `api/.dockerignore` — a `.dockerignore`
  only applies to files at the root of whatever `context:` a build uses,
  so `api/.dockerignore` would have been silently ignored the moment the
  context changed away from `./api`.
- **Not verified**: no Docker available in this sandbox, so the rebuilt
  image was never actually built or run. Rebuild and retest before
  trusting this fully:
  `docker compose up -d --build` then `docker exec nextcloud-scanner-api ls -la /app/ansible`
  should show `scan_file.yml`, `ansible.cfg`, `group_vars/`, and
  `inventory.ini` all present.

### Incident: `Could not match supplied host pattern, ignoring: debian`

Next request past the previous three fixes failed on `--limit debian`
matching zero hosts. Plain inventory gap, not a bug: `ansible/inventory.ini`
shipped with only the placeholder `nextcloud01`/`nextcloud02` entries, and
this user's actual setup is a single Debian box running Nextcloud, the
`api` container, and Docker all together (the "Single host" topology in
README section 3), reporting hostname `debian` — nothing in inventory
matched that name.

- **Fix**: added a `debian` host entry to `ansible/inventory.ini`,
  targeting `ansible_host=host.docker.internal` — the `api` container
  needs a real SSH connection out to the actual host machine (not
  `ansible_connection=local`, which would run Ansible's `stat`/`copy`
  tasks against the *container's* filesystem instead of the host's, where
  Nextcloud's data actually lives). Also added
  `extra_hosts: ["host.docker.internal:host-gateway"]` to the `api`
  service in `docker-compose.yml`, since `host.docker.internal` only
  resolves automatically on Docker Desktop (Windows/Mac) — this makes it
  resolve on plain Linux Docker Engine too.
- Since `inventory.ini` is baked into the `api` image (see the previous
  incident), this requires `docker compose up -d --build` to take effect
  — same caveat as before.
- **Two things this does NOT fix, and the user hasn't confirmed yet**:
  (1) an SSH server must be reachable on the Debian host itself from
  inside the container, and (2) a `scanner_svc` service account must
  exist there with the `api` container's SSH key
  (`/home/scanner/.ssh/id_ed25519`, bind-mounted from `./ssh` per
  `docker-compose.yml`) in its `authorized_keys`, plus read access to the
  Nextcloud data directory (README section 3, "Target host setup"). If
  the next error is an SSH auth/connection failure, that's this
  prerequisite not being done yet, not a new bug — check that section
  before assuming something else broke.

### Incident: `couldn't resolve module/action 'community.docker.docker_container'`

SSH connectivity and host targeting were confirmed working at this point
(the user fixed the inventory hostname themselves) — this failure was
purely local to the `api` container, at the `docker_container` task in
`scan_file.yml`.

- **Cause**: `api/Dockerfile` runs `ansible-galaxy collection install
  community.docker ansible.posix` as **root**, before `USER scanner`
  takes effect later in the same file. `ansible-galaxy` with no `-p` flag
  installs to `~/.ansible/collections`, which at that point in the build
  resolves to `/root/.ansible/collections`. At runtime the container
  actually runs as the unprivileged `scanner` user (`HOME=/home/scanner`),
  which can't even traverse into `/root` (mode 0700) — so the collection
  that provides `community.docker.docker_container` was invisible to the
  process that needed it. This is a generic trap for any Dockerfile that
  installs Ansible collections before switching to a non-root `USER`, not
  specific to this project.
- **Fix**: install to `/usr/share/ansible/collections` instead (one of
  Ansible's default collection search paths, independent of `$HOME`) via
  `ansible-galaxy collection install ... -p /usr/share/ansible/collections`,
  then `chmod -R a+rX` it so any runtime user can read it. Also added
  `collections_path = /usr/share/ansible/collections` to
  `ansible/ansible.cfg` under `[defaults]` — explicit rather than relying
  on Ansible's implicit default search order, same reasoning as the
  `local_tmp`/`ANSIBLE_CONFIG` fix earlier in this log.
- Requires `docker compose up -d --build` to take effect (image rebuild,
  same as every fix so far that touches `api/Dockerfile`).
- **Not verified**: no Docker available in this sandbox. If this specific
  module still fails to resolve after rebuilding, check
  `docker exec nextcloud-scanner-api ls -la /usr/share/ansible/collections/ansible_collections`
  — should show `community/docker` and `ansible/posix` directories.

### Incident: `ansible_failed`, rc=4, empty `stderr_tail` (silent failure)

The user rebuilt with the collections-path fix above and the failure mode
changed — same rc=4 (Ansible's "parser/module-resolution error" exit
code), but this time `stderr_tail` was completely empty, giving no clue
what actually broke.

- **Root cause of the *silence*, not the failure itself**: Ansible does
  not consistently write `ERROR!`-prefixed messages to stderr — many
  parser/module-resolution failures go to **stdout**.
  `api/ansible_runner.py` only ever logged `proc.stderr`, so any error
  that Ansible wrote to stdout was completely invisible in our own logs,
  even though the process actually printed it somewhere. This is a real
  observability gap in the logging code itself, independent of whatever
  the underlying rc=4 cause turns out to be.
- **Fix**: `ansible_runner.py`'s `ansible_failed` log event now includes
  `stdout_tail` alongside `stderr_tail` (both last 2000 chars). If a
  failure is ever logged with both tails empty again, that's worth
  treating as its own bug (e.g. the process died before producing output,
  or output exceeded buffering in a way `subprocess.run(capture_output=True)`
  doesn't handle — unlikely, but check `proc.returncode` context first).
- **The underlying rc=4 cause itself was NOT diagnosed** — no Docker in
  this sandbox to reproduce it, and the old logs don't contain the actual
  message. Don't assume it's the same collections issue recurring; it
  could be a `docker_container` argspec mismatch (e.g. a community.docker
  version fetched by the unpinned `ansible-galaxy collection install`
  no longer supports the `cleanup` parameter used in `scan_file.yml`'s
  `docker_container` task — check this if it recurs) or something
  unrelated. Fast checks that don't require reconstructing a full extra-vars
  file: `docker exec nextcloud-scanner-api ansible-galaxy collection list`
  and `docker exec nextcloud-scanner-api sh -c "ANSIBLE_CONFIG=/app/ansible/ansible.cfg ansible-doc community.docker.docker_container"`
  — if `ansible-doc` resolves the module fine, the failure is inside the
  task's execution, not module resolution, and the next rebuild's
  `stdout_tail` should show why.

### Incident: HTTP 500 with no error visible anywhere in server logs

Ansible actually succeeded this time (`ansible-playbook` exited 0, no
`ansible_failed`/`ansible_error` log event at all - straight from
`ansible_run_start` to `scan_completed`), but the scan still ended in
`status: ERROR`, `http_status: 500`, and nothing in the JSON logs said why.

- **Root cause of the failure itself**: not fully diagnosed - see below.
  The user had changed `ansible_user` to `root` (inventory.ini) and
  `scanner_service_user` to `root` (group_vars/all.yml), which rules out
  the permission-denied theory that would otherwise fit (root can chown
  anything, no `become` needed) — so it's something else inside
  `scan_file.yml`'s main `block:` (the `realpath -e` check, an `assert`,
  the `stat` size/regular-file checks, or the `docker_container` task
  itself). A plausible candidate worth checking first: if Nextcloud runs
  inside its own container with `/var/www/nextcloud/data` only visible
  inside *that* container (not bind-mounted to the actual Debian host's
  filesystem), then `realpath -e` run over a plain SSH connection to the
  host itself would correctly report the file doesn't exist there — this
  is worth ruling out before assuming another config bug.
- **Root cause of the *invisibility*, a real bug, now fixed**: when a
  task inside `scan_file.yml`'s `block:` fails, the `rescue:` block
  catches it, writes `stage: "precondition_failed"` with a `message` into
  the result JSON, and lets `ansible-playbook` exit **0** (rescued, not
  failed) — so this never touches `ansible_runner.py`'s
  `ansible_failed`/`stdout_tail` logging at all (that only fires on
  non-zero exit). `api/scanner.py`'s `_interpret_ansible_result` read
  that `message` and put it in the HTTP response body, but never logged
  it server-side — unlike the sibling `sha256_mismatch` branch two lines
  below it, which already did. So the *only* place the actual reason ever
  appeared was the client's own HTTP response body, invisible in
  `docker logs`.
- **Fix**: `api/scanner.py`'s `precondition_failed` branch now logs a
  `precondition_failed` warning event with the message, matching the
  `sha256_mismatch` branch's existing pattern. This is a **pure Python
  change - no Docker rebuild needed**, unlike almost every other fix in
  this log; `docker compose restart api` (or nothing at all, if the
  container reloads uvicorn on file change) is enough.
- **Immediate way to see the message without any rebuild**: it's already
  in the HTTP response body the client received - check what the Bash
  script / curl call actually printed, or re-run the request with curl
  directly against `/api/v1/scan` and read the JSON `message` field.
- Separately, `docker-compose.yml`'s `read_only`, `cap_drop: [ALL]`, and
  `security_opt` are now commented out on the `api` service (presumably
  for troubleshooting). Worth restoring once the underlying issue here is
  found — connecting as `root` over SSH is also a real departure from
  this project's stated least-privilege design (see README "Target host
  setup" and section 6's security summary table), not just a debugging
  convenience; flag this back to the user rather than silently treating
  it as the new normal.

### Incident: `argument 'tmpfs' is of type <class 'dict'> ... cannot be converted to a list`

The `precondition_failed` logging fix from the previous incident paid off
immediately - the real message was visible on the very next attempt.

- **Cause**: a genuine bug in `scan_file.yml`, not an environment/config
  issue - present since this file was first written. The
  `docker_container` task's `tmpfs` option was written in Docker
  Compose's dict syntax (`tmpfs: {/tmp: "rw,noexec,nosuid,size=64m"}`),
  but `community.docker.docker_container`'s `tmpfs` parameter takes a
  **list** of `"path:options"` strings (`docker run --tmpfs` syntax), not
  a dict. This was silently breaking every single scan attempt that made
  it this far - it just took this many other fixes to actually reach this
  task.
- **Fix**: changed to `tmpfs: ["/tmp:rw,noexec,nosuid,size=64m"]` (list
  form) in `ansible/scan_file.yml`.
- Requires `docker compose up -d --build` — baked into the image, same as
  every other `scan_file.yml`/`ansible.cfg`/`group_vars` edit in this log.
- **Not verified**: no Docker in this sandbox. If the `docker_container`
  task fails again after rebuilding, check the message the
  `precondition_failed` log event now surfaces before assuming it's the
  same bug recurring — the fix pattern here (fail fast with the real
  library/module error visible in logs) is exactly why this was findable
  in one round-trip instead of several more blind guesses.

### Incident: `postgres` container crash-loops on `docker compose up` — `ls: can't open '/docker-entrypoint-initdb.d/': Permission denied`

First real `docker compose up` of the platform-layer pass (against live
Docker, outside this sandbox) never got PostgreSQL running at all — it
crash-looped immediately, which also cascaded into `api`/`worker`
reporting "dependency postgres failed to start" since the healthcheck
never passed.

- **Cause**: the `postgres` service in `docker-compose.yml` had
  `cap_drop: [ALL]` and `security_opt: [no-new-privileges:true]` applied
  to it — copied from the same hardening pattern used on the
  api/worker/ClamAV containers, which DO need it (they run
  attacker-influenced code paths). The official `postgres:16-alpine`
  image's entrypoint starts as root specifically so it can `chown`/`chmod`
  `PGDATA` and then `gosu` down to the `postgres` user for the actual
  server process — and reading a bind-mounted directory it doesn't
  strictly "own" by matching UID (here, `./db/migrations:/docker-entrypoint-initdb.d:ro`,
  bind-mounted from the Windows host) as root depends on
  `CAP_DAC_OVERRIDE`, the capability that lets root bypass normal file
  permission checks. `cap_drop: [ALL]` removes exactly that, so the
  entrypoint's own directory listing of `/docker-entrypoint-initdb.d/`
  failed with a plain `EACCES` even though the process was nominally
  running as root - not a bug in any file this project wrote, but an
  incompatibility between "harden every container identically" and how
  the upstream postgres image is designed to start up.
- **Fix**: removed `cap_drop`/`security_opt` from the `postgres` service
  only (`docker-compose.yml`) — left in place, unchanged, on every
  container that actually executes scanner/attacker-influenced content.
  Postgres here only ever runs SQL from files this repo ships (the two
  migration files), never attacker-controlled bytes, so it doesn't need
  or benefit from the same threat-model treatment; forcing it to have
  identical hardening as the ClamAV/scanner containers was over-applying
  a good pattern to a place it didn't fit.
- **A second, more damaging consequence of the crash-loop, requiring
  manual cleanup**: the official entrypoint runs `initdb` (which
  populates `$PGDATA`, making the volume non-empty) BEFORE it processes
  `/docker-entrypoint-initdb.d/*` — so by the time the permission error
  hit, `initdb` had ALREADY completed and written files into the
  `postgres_data` named volume. Fixing the capability issue alone and
  restarting is NOT enough: PostgreSQL's own entrypoint only runs
  init-db files against a **fresh, empty** data directory, and after this
  crash-loop the volume is no longer empty — it just never got the
  migration SQL applied, since that step is exactly where it crashed.
  Restarting as-is would silently boot a PostgreSQL server with NO
  tables at all, and the API/worker would then fail every DB query
  against a database that looks "up" per the healthcheck. Since the
  volume never held anything but this failed half-initialization (no
  real scan history existed yet), the fix is to wipe and re-init it:
  ```bash
  docker compose down
  docker volume rm postgres_data   # named exactly this - see docker-compose.yml's volumes: block
  docker compose up -d
  docker compose logs -f postgres  # confirm both migrations apply cleanly this time
  ```
  **Do not run `docker volume rm postgres_data` against a deployment
  that has ever had real scan history in it** — check
  `docker exec nextcloud-scanner-postgres psql -U scanner -d scanner -c "SELECT count(*) FROM scans;"`
  first if there's any doubt; this is only safe here because the
  crash-loop happened on the very first `docker compose up` of a brand
  new deployment.
- **Not independently re-verified against a live stack** in this
  sandbox (no Docker available here) - this fix was derived by reading
  the official postgres entrypoint's known startup sequence and matching
  it against the exact symptom (root process, permission-denied directory
  listing, no chown/gosu errors reported before it), not by reproducing
  and re-testing the crash-loop locally. If PostgreSQL still fails to
  start after this fix, check `docker compose logs postgres` for a
  DIFFERENT error message before assuming this same root cause recurred.

**Follow-up — the `cap_drop` theory above was wrong, or at best
incomplete.** The user rebuilt with `cap_drop`/`security_opt` removed
from `postgres` and got the exact same
`ls: can't open '/docker-entrypoint-initdb.d/': Permission denied`
crash-loop, unchanged. Re-reading the actual upstream
`docker-entrypoint.sh` more carefully: when the container starts as root,
the very first thing `_main` does (before `initdb`, before touching
`/docker-entrypoint-initdb.d` at all) is `exec gosu postgres
"$BASH_SOURCE" "$@"` — the ENTIRE rest of the script, including the
`/docker-entrypoint-initdb.d` listing, re-executes as the unprivileged
`postgres` OS user. That re-exec happens unconditionally, independent of
`cap_drop`/capabilities entirely — so removing `cap_drop: [ALL]` could
never have fixed a permission problem that only ever manifests for the
non-root `postgres` user in the first place. The real cause is a
Windows/Docker-Desktop bind-mount reliability problem: a directory
bind-mounted from the Windows host (`./db/migrations:/docker-entrypoint-initdb.d:ro`)
does not reliably present as listable to a non-root, non-owning user
inside the Linux container — the SAME class of bug already logged above
under "the playbook could not be found" for `ansible/`, which was fixed
there by baking the directory into the image instead of bind-mounting it
at runtime.

- **Actual fix**: added `db/Dockerfile` (`FROM postgres:16-alpine` +
  `COPY migrations/ /docker-entrypoint-initdb.d/`) and changed
  `docker-compose.yml`'s `postgres` service from `image: postgres:16-alpine`
  to a `build: {context: ./db, dockerfile: Dockerfile}` block, removing
  the `./db/migrations:/docker-entrypoint-initdb.d:ro` bind mount
  entirely. This is now the THIRD place in this project
  (`ansible/`, and now `db/migrations/`) where a runtime directory bind
  mount was tried first and turned out to be unreliable specifically
  under Windows/Docker Desktop, and baking the content into the image at
  build time was what actually worked. **If a future change adds a new
  directory that needs to be readable inside any of these containers,
  bake it into the image by default — don't reach for a bind mount
  first** in this environment; that pattern has now failed twice for
  unrelated content (Ansible playbooks, SQL migrations) for the same
  underlying reason.
- Requires `docker compose up -d --build` (or `--build postgres`
  specifically) to pick up the new build stage - a plain `docker compose
  up -d` without `--build` will keep trying to pull/reuse the old
  `postgres:16-alpine` image reference from before this fix if it's
  still cached under that tag.
- The `cap_drop`/`security_opt` removal from the previous entry is
  **harmless and left in place** (postgres genuinely doesn't need that
  hardening tier, per the reasoning above), but it was never the actual
  fix for this specific symptom - filed here as a correction so a future
  session doesn't re-apply a `cap_drop` theory to a similar-looking bind
  mount problem in this project again.
- Same volume-wipe caveat as above still applies if `initdb` already ran
  against a half-initialized `postgres_data` volume before this fix
  landed: `docker compose down && docker volume rm postgres_data &&
  docker compose up -d --build`, and again, only if the deployment never
  held real scan history.
- **Not independently re-verified against a live stack** — still no
  Docker in this sandbox. The `ansible/` precedent for baking a directory
  into an image at build time is well-established and already proven to
  work in this exact project, which is why this fix is higher-confidence
  than the withdrawn `cap_drop` theory, but it has not actually been run
  against a real `docker compose up` yet either.

### Incident: the test suite never actually caught `PANEL_SESSION_COOKIE_SECURE` - a false-positive login test

The user hit "login succeeds but every page immediately bounces back to
`/login`" against a real deployment (root cause: `PANEL_SESSION_COOKIE_SECURE`
defaults to `true`, and a `Secure` cookie is never sent back over plain
HTTP - see README "Troubleshooting"). While adding tests for the new
panel upload page (`panel/upload.py`), the exact same failure reproduced
inside the unit test suite itself - `tests/conftest.py` never set
`PANEL_SESSION_COOKIE_SECURE`, so it defaulted to `true` there too, and
`fastapi.testclient.TestClient` talks to the app over plain
`http://testserver`. Any test that logged in and then made a follow-up
authenticated request should have failed for the identical reason the
user hit in production.

- **Why this was never caught**: `tests/test_api.py::test_login_with_correct_credentials_grants_dashboard_access`
  called `client.get("/dashboard")` WITHOUT `follow_redirects=False`.
  With redirects followed (`TestClient`'s default), an unauthenticated
  request to `/dashboard` 303s to `/login` - and `/login` itself renders
  a normal `200 OK` login page. The test's only assertion,
  `dash_resp.status_code == 200`, was therefore true whether or not the
  session actually worked; it was silently asserting "some page loaded
  successfully," not "the dashboard loaded." This is a real, structural
  test bug that predates this session — a passing test that doesn't
  test what its name says it tests can hide exactly this class of
  regression indefinitely.
- **Fix**: added `os.environ.setdefault("PANEL_SESSION_COOKIE_SECURE", "false")`
  to `tests/conftest.py` (matching how the test client actually talks to
  the app - plain HTTP - the same way a real non-TLS-terminated
  deployment does), and fixed the existing test to use
  `follow_redirects=False` plus an actual content assertion
  (`b"Dashboard" in dash_resp.content`) so a broken session fails loudly
  instead of silently redirecting to a page that happens to also return
  200.
- **New coverage added**: `tests/test_panel_upload.py` (the new manual
  upload page) deliberately logs in and pulls the real CSRF token out of
  the rendered form via regex rather than mocking `verify_csrf` away -
  this exercises the actual session/cookie/CSRF round trip end-to-end
  for every test in that file, so this exact bug class would fail loudly
  there too if it ever regressed.
- **Verified**: full suite (120/120) passes with the fix; reverting just
  the `conftest.py` line while keeping the corrected `follow_redirects=False`
  assertion reproduces the user's exact production symptom inside the
  test suite (confirmed manually during this fix, not left as a
  standing regression test - see the `panel/csrf.py` round trip in
  `test_panel_upload.py` for the closest thing to one).

### Incident: "Request Entity Too Large" on every file upload, and Nextcloud scans never producing a result

Two independent, unrelated bugs, both reported by the user in the same
session, both real:

**1. `MaxBodySizeMiddleware` (`api/main.py`) applied its small,
metadata-only limit to the new upload endpoints too.** This middleware
predates the platform layer - back when `/api/v1/scan` (a small JSON
payload) was the ONLY endpoint that existed, a hard 16 KiB
(`MAX_REQUEST_BODY_BYTES`) `Content-Length` cap made sense for
everything. The platform rewrite added `POST /api/v1/files/upload` and
the panel's `POST /upload`, both of which legitimately carry actual file
bytes up to `MAX_FILE_SIZE` (default 5 GiB) - but nobody exempted them
from this middleware, so EVERY upload above 16 KiB was rejected with 413
before FastAPI's own routing even saw the request. Both upload endpoints
already enforce their own size limit correctly (mid-stream, in
`routes_upload.py::stream_upload_to_staging`) - this middleware's
Content-Length pre-check was pure dead weight for them, just wrong dead
weight. **Fix**: `MaxBodySizeMiddleware.dispatch` now skips the check
entirely for any path starting with `/api/v1/files/upload` or `/upload`.
Pure Python change, no rebuild-and-redeploy caveats beyond the normal
`docker compose up -d --build api`.

**2. Two stale/broken config values, unrelated to the code above, left
over from the platform-layer's fetch/scan playbook split:**
- `ansible/inventory.ini`'s `[nextcloud]` host line was missing the
  space between the hostname and its first variable:
  `debianansible_host=192.168.150.87 ansible_user=root ...`. Ansible's
  INI inventory parser takes the first whitespace-delimited token as the
  literal hostname - so the actual inventory host was named
  `debianansible_host=192.168.150.87` (with NO `ansible_host` variable
  at all, since that got swallowed into the mangled name), not `debian`.
  `--limit debian` (what `ansible_runner.py` passes, matching the
  `NEXTCLOUD_HOSTS` key in `.env`) could never match anything, so the
  fetch stage failed on every single Nextcloud-triggered scan attempt -
  fixed by restoring the missing space. This is presumably a manual
  typo introduced while editing the inventory for a real deployment (the
  file this project ships has the space).
- `.env`'s `ANSIBLE_SCAN_PLAYBOOK_PATH` still pointed at
  `/app/ansible/scan_pipeline.yml` - the single-file playbook from
  BEFORE the fetch/scan split (see the earlier "postgres crash-loop"
  incident's design-decision bullets for why that file no longer
  exists). This `.env` predates that split and was never updated when it
  happened. Since `ansible_scan_playbook_path` is shared by BOTH the
  legacy Nextcloud flow and direct uploads (see the "third pass"
  architecture bullets above), this broke the SCAN stage for every scan
  regardless of entry point, not just Nextcloud's - fixed by pointing it
  at `/app/ansible/scan_uploaded_file.yml` (the current correct default
  in `api/config.py`, which is what this value should have inherited if
  it were simply left unset).
- **Only these exact two values were changed** - the user explicitly
  asked not to touch anything else in `docker-compose.yml`/`.env`/
  `ansible/inventory.ini` they'd customized (e.g. `api`'s port mapping
  changed to `8000:8000` and `cap_drop`/`security_opt` commented out on
  `api`/`worker` were both left exactly as found - the latter matches
  the "HTTP 500 with no error" incident's pattern of temporarily
  loosening hardening while troubleshooting; worth revisiting once
  everything above is confirmed working).
- **Not independently re-verified against a live stack** - no Docker in
  this sandbox. If Nextcloud-triggered scans still don't produce a
  result after this fix, re-run the manual playbook commands in
  README section 9 with `-vvv` to see the real Ansible error, and check
  `docker exec nextcloud-scanner-worker ansible-inventory -i /app/ansible/inventory.ini --list`
  to confirm the host now parses as plain `debian` with `ansible_host`
  set correctly, rather than assuming this exact bug class recurred.

### New: `scripts/generic-file-upload-scanner.sh`

Added alongside the Nextcloud-specific script, for every OTHER
application/watcher (NFS/SMB shares, custom upload handlers, CI, etc.)
that wants scanning without the Nextcloud-specific SSH-fetch machinery -
see README section 5.4. Structurally similar to
`nextcloud-upload-scanner.sh` (external config file, no secrets on the
command line, same fail-closed exit code convention) but hits
`POST /api/v1/files/upload` directly with the actual file bytes and a
per-application API key, using `?wait=true` for a server-side
synchronous wait first and falling back to client-side polling via
`GET /api/v1/scans/{id}` only if that server-side wait's own cap
(`SYNC_WAIT_MAX_TIMEOUT_SECONDS`) is hit before the scan finishes. Unlike
the Nextcloud flow, this integration path has no delete-on-infected
step - it only reports the verdict; a given watcher's own logic decides
what to do with an INFECTED/ERROR exit code. Not yet exercised against a
live API - `bash -n` clean, but no end-to-end run in this sandbox.

### Incident: `chgrp failed` then, after fixing that, every scan errors with `PermissionError(13, 'Permission denied')` connecting to Docker

Two more real bugs, found live by the user immediately after the fixes
above, in the same overall area (worker container permissions) but
independent of each other and of the earlier `.env`/inventory fixes.

**1. `chgrp failed`** - `scan_uploaded_file.yml`'s "Fix ownership/permissions
on the staged file" task (and `run_one_scanner.yml`'s per-scanner output-dir
task) `chgrp`s files to `scanner_container_gid` (`"10001"`, the
ClamAV/scanner container's own GID - see `ansible/group_vars/scanner.yml`).
This runs as the worker's own unprivileged `scanner` OS user
(uid/gid 10002:10002, `become: false` throughout - see the "no `become`"
design note above). An unprivileged process can only change a file's
GROUP to a group it already belongs to - and nothing anywhere granted
the `scanner` user membership in group 10001. This was never actually
exercised against live Ansible/Docker before this session (every earlier
build/verification pass in this file explicitly says so) - it's a
latent bug in the original two-server design, not something the
platform-layer rewrite introduced, and it affects BOTH transfer modes
(`ansible_fetch` and `direct_upload`) equally, since both share this one
scan-stage playbook. **Fix**: added `"10001"` to `docker-compose.yml`'s
`worker` service's `group_add:` list, alongside the existing
`DOCKER_GID` entry - same mechanism, same reason: give the unprivileged
`scanner` user supplementary group membership at container-start time so
its own unprivileged `chgrp`/`chown` calls succeed. No image rebuild
needed, just `docker compose up -d worker`.

**2. `Error connecting: Error while fetching server API version: ('Connection aborted.', PermissionError(13, 'Permission denied'))`** -
surfaced identically for every scanner, on every scan, once (1) was
fixed. This is the Python `docker` SDK (used internally by
`community.docker.docker_container`) failing to open
`/var/run/docker.sock` at all - a DIFFERENT permission problem than (1),
one level earlier in the pipeline (can't even talk to the Docker daemon
to start the scan container, let alone run one). `docker-compose.yml`
already had a `DOCKER_GID` mechanism for exactly this
(`group_add: ["${DOCKER_GID:-999}"]`), but the user's `.env` still had
the template's placeholder value (`999`), never updated to their actual
system's value. **Critically, `getent group docker` - the method this
project's own docs and `.env.example` comment recommended - does NOT
reliably answer this on Docker Desktop (Windows/Mac)**: the daemon runs
inside its own VM, so the value on the Windows/WSL host's own group
table has no guaranteed relationship to the GID that actually owns the
socket. The reliable method, confirmed working here: run a throwaway
container that mounts the socket and asks the DAEMON's own view of the
file directly -
`docker run --rm -v /var/run/docker.sock:/var/run/docker.sock alpine stat -c '%g' /var/run/docker.sock`
- which returned `996` for this user (not `999`, and not whatever
`getent group docker` would have said on the Windows side, which was
never actually checked because this method makes that unnecessary).
**Fix**: set `DOCKER_GID=996` in `.env`, `docker compose up -d worker`
to recreate (not rebuild) the container, verified via
`docker compose exec worker id` showing 996 in the `groups=` list.
Updated `.env.example`'s comment and README's troubleshooting entry to
lead with the `docker run ... stat` method rather than `getent group
docker`, which is actively misleading advice on Docker Desktop
specifically - a future session should not re-suggest `getent group
docker` as the primary fix for this symptom.

- **Sequencing note for anyone debugging a similar setup from scratch**:
  these two errors necessarily surface ONE AT A TIME, in this exact
  order - permission (2) (can't reach the Docker daemon at all) would
  have blocked the container from ever starting, meaning permission (1)
  (`chgrp` on files that only exist once staging succeeds) would never
  even have been reached if `DOCKER_GID` were still wrong. That's not
  what happened here because `chgrp` happens in a task BEFORE the
  `docker_container` task in `scan_uploaded_file.yml`/`run_one_scanner.yml`
  - so fixing (1) first was necessary just to expose (2). Don't assume a
  single fix from this log resolves everything in one pass; re-check the
  actual `scan_results.raw_output` (via the panel's scan detail page, or
  `SELECT scanner_name, status, raw_output FROM scan_results WHERE scan_id = '...'`)
  after EVERY fix in this area before assuming the pipeline is fully
  working.
- **Not independently re-verified end-to-end** - both fixes were derived
  from the user's own live error output (not reproduced in this
  sandbox, which has no Docker). If a scan still fails after both fixes,
  get the `raw_output` for that specific `scan_id` again first, the same
  way - don't assume it's a repeat of either bug above without checking.

### Incident: stale `nextcloud-scanner-clamav` image (`/scan/input` not found), then `cannot create /output/result.json: Permission denied`

Two more, found live in sequence right after the fixes above.

**1. Stale ClamAV image.** `docker/scan.sh` errored with paths from the
OLD pre-platform-layer mount layout (`/scan/input`, `/scan/output`) even
though the repo's current `docker/scan.sh`/`docker/Dockerfile` both
correctly use `/scan` + `/output` (see the "mount points changed"
design-decision bullet above). Root cause: `nextcloud-scanner-clamav:latest`
is NOT one of `docker-compose.yml`'s services - it's built via a separate,
manual `docker build -t nextcloud-scanner-clamav:latest -f docker/Dockerfile
docker/` command (see README/CLAUDE.md "Commands") - so `docker compose up
-d --build` never rebuilds it. The user's local image predated the mount
layout change. **Fix**: no code change - just re-run that `docker build`
command. Worth considering for a future pass: fold this image into
`docker-compose.yml` as a `build:`-only service (no `command:`/`ports:`,
never started directly) so `docker compose build` covers it too and this
exact staleness trap can't recur - not done in this session since it's a
structural change beyond what was asked, flagging it here instead.

**2. `cannot create /output/result.json: Permission denied`**, immediately
after fixing (1). The per-scanner output directory
(`run_one_scanner.yml`'s "Prepare output directory for {{ scanner_item.slug }}")
was `mode: "0770", owner: scanner_service_user, group: scanner_container_gid`
- and the scan container runs as `user: "{{ scanner_container_uid }}:{{ scanner_container_gid }}"`
(10001:10001), which by ordinary Unix permission rules SHOULD satisfy
the directory's group-write bit (group 10001 matches). It didn't. The
INPUT mount (`mode: "0440"`, same owner/group scheme, `:ro`) DID work
correctly for this same scan - ruling out a wholesale bind-mount
path-resolution mismatch (if the sibling ClamAV container were seeing a
completely different/disconnected directory than what Ansible chmod'd,
reading would have failed too, with "no input file found", not gotten
as far as actually running `clamscan`). That leaves Docker Desktop's
bind-mount permission/identity translation for a DooD sibling container
(`worker` starts `nc-scan-*` via the mounted `/var/run/docker.sock`,
making it a sibling, not a child, of `worker`) as the most likely
explanation - genuinely reliable READS but unreliable UID/GID-based
WRITE permission enforcement for this exact cross-container bind-mount
shape is consistent with (though not conclusively proven to be) a
Windows Docker Desktop filesystem-sharing quirk - this project has
already hit two OTHER, different Docker-Desktop bind-mount reliability
problems this session (`ansible/`, `db/migrations/` - both fixed by
baking content into images instead of bind-mounting at runtime; this one
is different in kind since it's about a sibling container's write
permissions, not directory visibility, so that fix pattern doesn't
directly apply here).
- **Fix**: changed that task's `mode` from `"0770"` to `"0777"` in
  `ansible/tasks/run_one_scanner.yml`. Deliberately narrow: only the
  per-scan, per-scanner OUTPUT subdirectory (never shared across
  scans/scanners, receives nothing but `result.json` from one already
  fully-sandboxed - `network_mode: none`, `cap_drop: ALL`,
  `no-new-privileges`, non-root, ephemeral, `cleanup: true` - container).
  The INPUT mount (the actual file being scanned) is untouched, stays
  `:ro` and tightly permissioned regardless. Sidesteps the whole
  UID/GID-matching question rather than resolving it, since the exact
  mechanism was not confirmed, only inferred from behavior.
  `ansible/` is baked into the `api`/`worker` image
  (`api/Dockerfile: COPY ansible/ /app/ansible/`), so this requires
  `docker compose up -d --build worker` (rebuilding `api` too, since they
  share one image, is harmless but not strictly required for this
  specific fix) to take effect - a plain restart will keep running the
  old baked-in copy.
- **Not independently re-verified against a live stack** - no Docker in
  this sandbox; both fixes were derived from the user's own live error
  output. If a scan still fails with a DIFFERENT permission error after
  this, that's evidence the Docker-Desktop-translation theory above is
  wrong (or incomplete) and the parent `{{ staging_dir }}/output`
  directory (still mode 0770, unchanged) or something earlier in the
  chain needs the same treatment - check `raw_output` again before
  assuming this exact fix should have covered it.

### Incident: the 0777 fix above did NOT work - real root cause was a DooD sibling-container bind-mount path mismatch, not a permission-bits problem

The `mode: "0777"` fix from the previous incident was tried live and
made no difference - EXACT same
`cannot create /output/result.json: Permission denied`. Since 0777
(rwxrwxrwx) grants write to literally any UID/GID, a permission-bits
explanation is now ruled out entirely. Re-examined from scratch.

**Real root cause**: `run_one_scanner.yml`'s `community.docker.docker_container`
task bind-mounts `{{ input_dir }}:/scan:ro` / `{{ output_dir }}/.../:​/output:rw`
- absolute paths that are only meaningful INSIDE the `worker` container
(via the `staging_data` named volume mounted there at
`/var/lib/upload-scanner`). But the scanner container `worker` starts is
a SIBLING, not a child - `worker` reaches the Docker daemon through the
bind-mounted `/var/run/docker.sock`, and the DAEMON resolves bind-mount
SOURCE paths against ITS OWN filesystem, not against the calling
container's mount namespace. A path like
`/var/lib/upload-scanner/staging/<scan_id>/input` does not exist on the
daemon's own root filesystem at all (it only exists as a view INTO the
`staging_data` volume, provided BY the volume driver, INSIDE containers
that explicitly mount that volume) - so the bind mount silently produces
an empty, disconnected directory instead of erroring. This is not a
Windows/Docker-Desktop-specific bug (unlike the two OTHER, different
bind-mount issues logged earlier for `ansible/` and `db/migrations/`) -
it's a fundamental property of Docker-outside-of-Docker (DooD) sibling
containers, on any OS, and reads through this exact `/scan` mount had
apparently never actually been exercised successfully before (every
prior build-status note in this file says as much).
- Re-examining the earlier "chgrp failed" / "no input file found"
  symptoms in this light: those were most likely THE SAME underlying
  wrong-directory problem all along, not distinct permission-bit issues -
  the `chgrp`/`0777` fixes were real, harmless, defensible improvements
  in their own right (worker's own uid needing group 10001, tighter vs.
  looser directory modes) but were not actually what was blocking things.
- **Fix (structural, not another permission tweak)**: `run_one_scanner.yml`
  now mounts the `staging_data` NAMED VOLUME (referenced by name -
  `"staging_data:/staging_ro:ro"` / `"staging_data:/staging_rw:rw"`, NOT
  by absolute path) instead of a raw bind-mount path. Docker resolves a
  named-volume reference identically regardless of which container asks,
  sidestepping the DooD path-resolution problem entirely. Trade-off:
  each scanner container can now see the WHOLE staging volume (all
  scans) rather than a narrowly bind-mounted single directory -
  mitigated by keeping a read-only mount for input, a separate
  read-write mount for output only, and everything else the container
  already had (`network_mode: none`, `cap_drop: ALL`, non-root,
  ephemeral). `ansible/group_vars/scanner.yml` gained
  `staging_data_volume_name`/`staging_data_container_mount_point` (must
  match `docker-compose.yml`'s `- staging_data:/var/lib/upload-scanner`
  exactly - if that mount point is ever changed, this must change with
  it, in the same PR). `docker/scan.sh` now reads
  `$SCAN_INPUT_DIR`/`$SCAN_OUTPUT_DIR` (set unconditionally by
  `run_one_scanner.yml`, merged with the scanner's own `env_vars`)
  instead of hardcoded `/scan`/`/output`, falling back to those same
  hardcoded defaults if unset (so a manual `docker run` test of the
  image still works unchanged). The `{{FILE}}`/`{{OUTPUT}}` placeholder
  mechanism for admin-registered scanners resolves to the new
  sibling-visible paths now, transparently - no change needed to how
  admins write `scan_command`.
- **Follow-up worth doing, not done here**: Docker Engine 25+ supports
  `mounts: volume_options.subpath`, which would restore narrow
  per-scan/per-scanner mount scoping (the ORIGINAL intent) while still
  correctly resolving via the named volume. Not used in this fix because
  `community.docker`/Docker Engine version compatibility wasn't verified
  and the user needed a working fix on the first try, not another
  iteration - the broader whole-volume mount above is guaranteed to work
  on any Docker version. Revisit once compatibility is confirmed.
- Requires `docker compose up -d --build worker` (ansible/ is baked into
  the image) AND rebuilding the ClamAV image again
  (`docker build -t nextcloud-scanner-clamav:latest -f docker/Dockerfile docker/`,
  since `docker/scan.sh` changed) - both together this time.
- **Not independently re-verified against a live stack** - no Docker in
  this sandbox; this fix is a considered, structural response to the
  DooD sibling-container mounting problem, not something reproduced and
  re-tested here. If a scan still fails with a DIFFERENT error after
  this, get `raw_output` again - don't assume another permission-bits
  tweak is the answer this time either.

### Improvement: human-readable log format (`LOG_FORMAT=text`) + per-scanner detail in `scan_completed`

Prompted directly by the user's own feedback debugging the incident
above - raw JSON log lines with a terse `reason: "1 scanner(s) failed:
ClamAV"` required a separate `psql`/panel round-trip every time to find
out WHY, which is exactly what made the incident above take as many
turns as it did.

- `api/scanner.py`'s `scan_completed` log event now includes a
  `scanner_results` field (scanner name/status/threat/message, one entry
  per scanner) whenever the overall status isn't `CLEAN` - the same
  per-scanner detail already stored in `scan_results.raw_output` in
  PostgreSQL, now ALSO right there in the log line, no query needed.
  Omitted for `CLEAN` results to keep the common case's log line short.
- New `LOG_FORMAT` setting (`api/config.py`, default `json` - unchanged
  behavior unless explicitly opted into). `LOG_FORMAT=text` switches to
  `logging_config.py::TextFormatter`: one compact, ANSI-colored line per
  event (`HH:MM:SS LEVEL logger event key=value ...`), with
  `scan_completed`'s `scanner_results` pretty-printed as indented
  sub-lines - so the exact failure a scanner hit is visible directly in
  `docker compose logs -f worker`, formatted for a human, without
  needing to touch the database at all. `LOG_FILE` output (if set)
  always stays JSON regardless of `LOG_FORMAT`, so a log file never ends
  up with embedded ANSI escape codes.
- **Found and fixed during the smoke test itself**: `TextFormatter`'s
  first draft used a Unicode box-drawing character (`└─`) for the
  per-scanner sub-line prefix, which crashed with `UnicodeEncodeError`
  under Windows' default `cp1252` console encoding the moment a
  non-CLEAN `scan_completed` event was logged - exactly the kind of
  Windows-specific footgun this project has hit repeatedly elsewhere.
  Replaced with plain ASCII (`->`) before this ever shipped; verified
  with a direct smoke test (not just `bash -n`/`py_compile` - those
  wouldn't have caught a runtime encoding crash).
- Pure Python change - `docker compose up -d --build` picks it up
  (bundled with the mount-scheme fix above in the same rebuild).

### Incident: two follow-on errors after the DooD mount-scheme fix, verified fix-by-fix instead of guessed

The named-volume mount fix above was correct, but two more distinct
bugs were hit and fixed IN SEQUENCE right after, each confirmed with
real evidence from the user before attempting the next fix, after two
earlier guesses (the `0777` mode change, and not initially realizing the
ClamAV image needed a SEPARATE rebuild) turned out to be wrong or
incomplete. Documenting the verification method here as much as the
bugs themselves, since guessing a third time would have cost the user
another full round-trip for nothing.

**1. `cannot create /output/result.json: Read-only file system`** (a
DIFFERENT error from the earlier `Permission denied` on the same path -
easy to misread as "still broken", but the error TEXT itself is the
diagnostic signal). Root cause: the user had rebuilt `worker`/`api`
(picking up the new Ansible mount scheme) but not the SEPARATE
`nextcloud-scanner-clamav` image - `docker/scan.sh` inside the
STILL-OLD image never read `$SCAN_OUTPUT_DIR` at all (that env var
support was added in the SAME commit as the mount-scheme fix), so it
fell back to its hardcoded `/output` - which, under the NEW mount
scheme, is no longer bind-mounted to anything (replaced by
`/staging_ro`/`/staging_rw`), leaving it as a plain directory on the
container's `read_only: true` root filesystem. Confirmed via
`docker run --rm --entrypoint cat nextcloud-scanner-clamav:latest /usr/local/bin/scan.sh`
showing the old hardcoded paths, BEFORE suggesting the fix (not after) -
this is the pattern to keep using: verify what's actually running
before proposing a change, especially now that this project has TWO
independently-rebuildable images (`api`/`worker` via `docker compose
--build`, ClamAV via its own separate `docker build`) that are easy to
get out of sync mid-debugging, as this incident shows directly. **Fix**:
rebuild the ClamAV image too - no code change needed, the code was
already correct.

**2. `find: '/staging_ro/staging/<scan_id>/input': Permission denied`** -
progress, not a regression: this confirmed the mount now resolves to a
REAL directory (a phantom/disconnected directory would have produced
"No such file", not "Permission denied" on a `find` that can see the
path exists but can't enter it). Root cause, found by comparing the two
transfer modes side by side: `fetch_from_nextcloud.yml` (the
`ansible_fetch`/legacy Nextcloud flow) already correctly creates
`input_dir` itself with `mode: "0750", group: scanner_container_gid` -
but `api/routes_upload.py::finalize_staged_upload` (the `direct_upload`
flow) creates the equivalent directory via a plain Python
`mkdir(parents=True, mode=0o750)`, which sets owner/group to the `api`
container's OWN identity (uid/gid 10002, its own "scanner" group) - NOT
`scanner_container_gid` (10001). `scan_uploaded_file.yml`'s existing
"Fix ownership/permissions on the staged file" task only ever fixed the
FILE inside that directory, never the DIRECTORY containing it - so a
scan container (uid/gid 10001:10001) could never even traverse INTO the
input directory to find the file, for `direct_upload` scans specifically.
This gap existed since the platform-layer rewrite first introduced
`transfer_mode=direct_upload`, but was never actually reachable/visible
until the DooD mount-resolution bug above was fixed - before that, scan
containers never reached a real, correctly-populated directory at all,
so this permission gap on the directory itself had no chance to surface.
**Fix**: added a new task to `scan_uploaded_file.yml` ("Fix
ownership/permissions on the staging INPUT directory itself") that
applies the SAME `mode: "0750", group: scanner_container_gid` fix
`fetch_from_nextcloud.yml` already does - redundant-but-harmless for
`ansible_fetch`, and the actual fix for `direct_upload`. Since this task
lives in the SHARED scan-only playbook, both transfer modes get it
applied consistently, and there is no plausible third transfer mode to
worry about missing this in the future.
- Requires `docker compose up -d --build worker api` (this specific fix
  is pure Ansible YAML - the ClamAV image does NOT need rebuilding again
  this time, since `docker/scan.sh` didn't change for this one).
- **Not independently re-verified against a live stack** - both fixes
  in this entry were derived from the user's own live error text and
  confirmed-before-fixing diagnostic output, not reproduced in this
  sandbox (no Docker here). If a scan still fails after this, get fresh
  `raw_output` again - three permission-adjacent bugs in a row in this
  exact area is enough that a fourth, different one showing up would not
  be shocking, and guessing again without fresh evidence would repeat
  the exact mistake this entry is documenting the fix for.
