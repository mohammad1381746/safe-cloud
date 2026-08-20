# File Security Scanning Platform

A generic, multi-scanner file security platform - not a "ClamAV API".
The original Nextcloud integration (a post-upload malware scan split
across a Nextcloud server and a Scanner Server) is now one client of a
**universal upload API** that any application, service, or pipeline can
call directly. Antivirus engines are pluggable (`scanners` +
`scanner_profiles` in PostgreSQL - ClamAV ships registered by default,
more can be added by an administrator without touching the scan
pipeline's code), results from every configured scanner are aggregated
by a policy engine, encrypted/password-protected files get their own
configurable policy, and every scan is permanently recorded and
browsable through a management panel with its own authentication, API
key management, and audit log.

```
Any application (Nextcloud, a web app, a CI pipeline, ...)
      |
      | POST /api/v1/files/upload  (Bearer API key)
      v
Scanner Server: API (FastAPI) --> PostgreSQL (queue + scan history)
      |                                  ^
      | polled by                       |
      v                                  |
Worker (Ansible, Docker, SSH) -----------+
      |
      +-- SSH/SFTP --> Nextcloud Server (only for the legacy path-reference flow)
      |
      +-- Docker --> one ephemeral, hardened container PER SCANNER in the
                      active profile (ClamAV by default; more can be
                      registered by an administrator)
```

The original two-server Nextcloud topology still works exactly as
before and is unchanged - see section 1a. The platform layer (sections
1b onward) is additive.

---

## 1a. Architecture: the original Nextcloud pipeline (read this first)

Same fundamental distinction as any post-upload scanner: **this is not a
pre-upload gate.** The file is already written to Nextcloud's data
directory, already in Nextcloud's database, before the Bash hook even
fires - Nextcloud's Workflow Script mechanism has no synchronous
pre-write hook that can block the upload transaction itself. This
project detects and reacts (quarantines/deletes) after the fact, fast,
but not before the file briefly existed. A true pre-upload gate would
require an upload-proxy in front of Nextcloud's own upload endpoints -
out of scope here.

**Fail-closed** remains the default throughout: if the API is
unreachable, the worker crashes, Ansible fails, the transfer fails, or
the hashes at any checkpoint (client claim -> Nextcloud actual ->
transferred actual -> scanned actual) disagree, the result is
`allowed: false`. Nothing in this codebase has a path that defaults to
"allow" when something goes wrong.

Docker runs **only** on the Scanner Server - the Nextcloud server never
gets Docker access, never runs a scan container, and no scan container
ever mounts the Nextcloud filesystem (it only ever sees a copy already
pulled onto the Scanner Server's own staging directory). This is a
deliberate blast-radius boundary: compromising a scanner (or a malicious
file exploiting a scanner bug) can't reach Nextcloud's data directly,
and compromising the Bash hook doesn't grant any Docker access at all.

Because transfer + scan can take longer than an HTTP request should
reasonably block on, `POST /api/v1/scan` (legacy) and
`POST /api/v1/files/upload` (universal) both return immediately
(`202 Accepted` + an id) once the request passes validation and a
database row is created. A background worker on the Scanner Server does
the actual work; callers poll `GET /api/v1/scan/{scan_id}` (legacy) or
`GET /api/v1/scans/{scan_id}` (universal, or `?wait=true` for
synchronous polling done server-side) for the result.

## 1b. Architecture: the platform layer

**Universal upload API** (`api/routes_upload.py`) - `POST
/api/v1/files/upload` accepts a file directly (multipart), authenticated
by a per-application API key rather than the Nextcloud hook's static
bearer token. The bytes are written straight to the Scanner Server's own
staging volume (the API container is the one deliberate exception to
"never touches local Docker/scan state" - see docker-compose.yml) - no
Nextcloud/Ansible/SSH round trip is needed for this path, so any
application can use it without ever standing up an SSH relationship to
anything.

**Pluggable scanners, not just ClamAV** (`api/scanners.py`,
`scanners` table) - an administrator defines a scanner's Docker image,
argument-array scan command (never a shell string, strictly validated -
see section 7), timeout, and CPU/memory limits through the panel.
`ansible/tasks/run_one_scanner.yml` runs each scanner in a profile as
its own isolated, hardened container; the CORE pipeline
(`api/scanner.py`) never has scanner-specific logic in it.

**Scanner profiles + aggregation policy** (`api/policy.py`,
`scanner_profiles` table) - a profile is a named, ordered list of
scanners plus an `aggregation_policy`: `ALL_MUST_PASS` (any error or
detection blocks - the default), `ANY_DETECTION` (only an actual
detection blocks; a scanner outage is tolerated if another scanner
reports clean), `FIRST_DETECTION` / `FIRST_SUCCESS` (decided by the
first scanner, in profile order, that detects / that completes). Every
individual scanner's result is stored (`scan_results` table) even though
only one profile decides the final verdict - nothing is ever thrown away.

**Encrypted-file policy** (`api/encryption_detect.py`, `api/policy.py`,
`encrypted_file_policies` table) - best-effort detection (ZIP/Office
structure inspection, `pypdf` for PDF; RAR/7z and legacy Office mostly
resolve to "unknown" rather than a false claim) feeds a per-category
policy (`ALLOW` / `DENY` / `QUARANTINE` / `MARK_FOR_REVIEW`, default
`DENY`) that skips scanning entirely and decides the verdict directly -
most scanners can't inspect content they can't decrypt anyway.

**API clients + scoped permissions** (`api/auth_apikey.py`,
`api_clients` table) - keys are SHA-256 hashed at rest (never plaintext,
shown once at creation/rotation), scoped to `scan.upload` /
`scan.read` (own scans only) / `scan.read_all`, and can be pinned to a
specific scanner profile so a client can never choose an arbitrary
scanner list - only what an administrator explicitly allows.

**Permanent history + audit log** (`db/migrations/0002_platform.sql`) -
every scan gets a row that outlives its staging files; every
administrative/security-relevant action (login, scanner/profile
changes, API key lifecycle, encrypted-policy changes, re-scans) is
recorded in `audit_log`, never auto-pruned unless explicitly enabled.

---

## 2. Directory structure

```
nextcloud-upload-scanner/
├── README.md
├── CLAUDE.md
├── .env.example
├── .dockerignore
├── docker-compose.yml            # Scanner Server stack: api, worker, postgres, freshclam-updater
├── requirements.txt
│
├── api/                           # Shared image for BOTH `api` and `worker` services
│   ├── main.py                    # HTTP: legacy /api/v1/scan, docs toggle, mounts panel + upload routers
│   ├── routes_upload.py           # Universal upload API: /api/v1/files/upload, /api/v1/scans/*
│   ├── worker.py                  # Polling job worker (DB queue, bounded concurrency, stale-job sweep)
│   ├── scanner.py                 # Per-job pipeline: transfer -> encryption check -> multi-scan -> policy -> cleanup
│   ├── scanners.py                # Scanner provider abstraction + strict command/config validation
│   ├── policy.py                  # Aggregation policy + encrypted-file policy engine
│   ├── encryption_detect.py       # Best-effort encrypted/password-protected file detection
│   ├── auth_apikey.py             # API key generation/hashing/verification/permission scoping
│   ├── ansible_runner.py          # Generic subprocess.run wrapper for all playbooks
│   ├── db.py                      # psycopg data access - scans, scanners, profiles, api_clients,
│   │                               #   encrypted policies, audit log, system settings, dashboard aggregates
│   ├── config.py                  # NEXTCLOUD_HOSTS, DB, staging, worker, panel, upload-API settings
│   ├── models.py                  # Pydantic request/response schemas (legacy /api/v1/scan)
│   ├── security.py                # Bearer auth (legacy), per-host path/host allowlisting
│   ├── logging_config.py          # Structured JSON logging
│   ├── Dockerfile                 # Build context = repo root (bakes in ansible/)
│   └── panel/                     # Management web panel (FastAPI + Jinja2 + HTMX + Bootstrap)
│       ├── auth.py                # PBKDF2 password hashing, session login/logout, lockout, audit
│       ├── csrf.py                # Double-submit session CSRF token helper
│       ├── routes.py              # /dashboard, /scans, /scans/{id}, re-scan
│       ├── admin_scanners.py      # /scanners CRUD
│       ├── admin_profiles.py      # /profiles CRUD (scanner selection + ordering + aggregation policy)
│       ├── admin_settings.py      # /settings/encrypted-files, /settings/api-clients, /settings/security, /audit
│       ├── upload.py              # /upload - manual browser upload, reuses routes_upload.py's staging helpers
│       └── templates/
│
├── scripts/
│   ├── nextcloud-upload-scanner.sh       # Nextcloud Flow hook (legacy path): POST, then poll until terminal
│   └── generic-file-upload-scanner.sh    # Any other app/NFS/SMB watcher: direct upload + API key (section 5.4)
│
├── config/
│   ├── nextcloud-upload-scanner.conf.example
│   └── file-upload-scanner.conf.example
│
├── ansible/
│   ├── ansible.cfg
│   ├── inventory.ini               # [nextcloud] and [scanner] groups
│   ├── fetch_from_nextcloud.yml    # Legacy path only: validate + SFTP-fetch onto the Scanner Server
│   ├── scan_uploaded_file.yml      # Scan-only playbook, shared by BOTH the legacy and universal-upload flows
│   ├── delete_infected_source.yml  # TOCTOU-checked deletion, nextcloud group only
│   ├── tasks/
│   │   └── run_one_scanner.yml     # Runs ONE scanner container; looped once per scanner in the active profile
│   └── group_vars/
│
├── docker/
│   ├── Dockerfile                  # ClamAV scan image (clamscan only) - the default registered scanner
│   ├── Dockerfile.freshclam
│   ├── freshclam-entrypoint.sh
│   └── scan.sh                     # Container entrypoint; mounts: /scan:ro, /output:rw
│
├── db/
│   ├── Dockerfile                  # FROM postgres:16-alpine, COPYs migrations/ in at build time
│   └── migrations/
│       ├── 0001_init.sql           # Original single-scanner schema
│       └── 0002_platform.sql       # scanners/profiles/api_clients/audit_log/etc + scans table extensions
│
├── tests/
│
└── systemd/
    ├── scanner-api.service         # Bare-metal alternative to the `api` container
    └── scanner-worker.service      # Bare-metal alternative to the `worker` container
```

---

## 3. Network / firewall requirements

| From | To | Port | Purpose |
|---|---|---|---|
| Nextcloud Server | Scanner Server | TCP 8000 (or 443 behind TLS) | Bash hook -> API (submit + poll) |
| Scanner Server | Nextcloud Server | TCP 22 | Worker -> Ansible SSH/SFTP (validate, fetch, delete) |
| Scanner Server | itself | Unix socket | Worker -> local Docker daemon |
| Scanner Server | itself | TCP 5432 (internal Docker network only) | api/worker -> PostgreSQL |
| Admin browser | Scanner Server | TCP 8000 (or 443) | Management panel |

**The Nextcloud Server needs**: nothing beyond outbound TCP 8000/443 to
the Scanner Server, and an SSH server reachable FROM the Scanner Server
on TCP 22. It does not need Docker, ClamAV, or any inbound port opened
for the scanner.

**The Scanner Server needs**: outbound TCP 22 to the Nextcloud Server, a
local Docker daemon, and (if PostgreSQL/panel access from elsewhere is
wanted) whatever additional ports you explicitly choose to expose -
`docker-compose.yml` does not publish PostgreSQL to any host port by
default.

Put a real TLS-terminating reverse proxy (nginx, Caddy, Traefik) in
front of port 8000 on the Scanner Server for anything beyond local
testing - this project itself serves plain HTTP; `PANEL_SESSION_COOKIE_SECURE=true`
(the default) requires HTTPS to actually set the session cookie, so the
panel will not log in over plain HTTP in a real deployment without a
proxy providing TLS.

---

## 4. Installation

### 4.1 Nextcloud Server (nextcloud01, e.g. 192.168.150.87)

This machine needs **no containers from this project at all**.

```bash
sudo install -o root -g root -m 0755 scripts/nextcloud-upload-scanner.sh \
    /usr/local/bin/nextcloud-upload-scanner.sh

sudo install -o root -g root -m 0600 config/nextcloud-upload-scanner.conf.example \
    /etc/nextcloud-upload-scanner.conf
sudo "${EDITOR:-nano}" /etc/nextcloud-upload-scanner.conf   # SCANNER_API_URL -> the Scanner Server

sudo touch /var/log/nextcloud-upload-scanner.log
sudo chown root:root /var/log/nextcloud-upload-scanner.log
sudo chmod 640 /var/log/nextcloud-upload-scanner.log

sudo apt-get install -y curl jq coreutils
```

**Grant the Scanner Server SSH access**, as a dedicated, low-privilege
service account - never root:

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin scanner_svc
sudo mkdir -p /home/scanner_svc/.ssh
sudo sh -c 'echo "<the Scanner Server worker'"'"'s public key>" >> /home/scanner_svc/.ssh/authorized_keys'
sudo chown -R scanner_svc:scanner_svc /home/scanner_svc/.ssh
sudo chmod 700 /home/scanner_svc/.ssh && sudo chmod 600 /home/scanner_svc/.ssh/authorized_keys

# Read AND delete access to the data directory (deletion is required for
# confirmed-infected files - see section 1 and the security summary below):
sudo setfacl -R -m u:scanner_svc:rwX /var/www/nextcloud/data
sudo setfacl -R -d -m u:scanner_svc:rwX /var/www/nextcloud/data
```

No `become`/sudo is used anywhere in the Ansible playbooks -
`scanner_svc`'s own ACL-granted permissions are sufficient. This account
never needs Docker, never needs to be in any admin group.

### 4.2 Scanner Server (scanner01, e.g. 192.168.150.100)

```bash
cd nextcloud-upload-scanner
cp .env.example .env
# Edit .env: SCANNER_API_TOKEN, NEXTCLOUD_HOSTS, POSTGRES_PASSWORD,
# DATABASE_URL, PANEL_SESSION_SECRET, PANEL_ADMIN_USERNAME, DOCKER_GID
# (getent group docker | cut -d: -f3)

mkdir -p ssh && cp /path/to/scanner_worker_key ssh/id_ed25519   # matches ansible/inventory.ini
chmod 600 ssh/id_ed25519

# Generate the panel admin password hash (run in any Python env with
# api/ on sys.path, or exec into the built image after the first build):
python3 -c "
import sys; sys.path.insert(0, 'api')
from panel.auth import hash_password
print(hash_password(input('Panel admin password: ')))
"
# paste the output into .env's PANEL_ADMIN_PASSWORD_HASH

docker build -t nextcloud-scanner-clamav:latest -f docker/Dockerfile docker/
docker compose up -d --build

curl -s http://127.0.0.1:8000/healthz
```

`db/migrations/0001_init.sql` and `0002_platform.sql` are baked into the
`postgres` image at build time (`db/Dockerfile` COPYs `db/migrations/`
to `/docker-entrypoint-initdb.d/` - not a runtime bind mount; see
CLAUDE.md's incident log for why) and applied automatically on first
start (the official postgres image runs every `*.sql` file there, in
filename order, against a fresh/empty data directory) - migration 2 also
seeds ClamAV as the first registered scanner and a "Standard" default
profile, so the platform is immediately usable without any manual setup.
Editing a migration file requires `docker compose up -d --build postgres`
to take effect, same as editing anything under `ansible/` requires
rebuilding `api`. On an EXISTING database (upgrading a prior install),
apply by hand instead, in order:

```bash
docker exec -i nextcloud-scanner-postgres psql -U scanner -d scanner < db/migrations/0001_init.sql
docker exec -i nextcloud-scanner-postgres psql -U scanner -d scanner < db/migrations/0002_platform.sql
```

Edit `ansible/inventory.ini`'s `[nextcloud]` entry to match your actual
Nextcloud host(s) and IP(s), then rebuild (`docker compose up -d --build`)
- the playbooks and inventory are baked into the image, not bind-mounted
(see CLAUDE.md's incident log for why). Each `[nextcloud]` entry's name
must exactly match a key in `.env`'s `NEXTCLOUD_HOSTS`.

Open the panel at `http://<scanner-server>:8000/login` and log in with
`PANEL_ADMIN_USERNAME` / the password you hashed above. From there:

1. **`/scanners`** - the seeded "ClamAV" scanner is ready to use; add
   more (Windows Defender, Sophos, YARA, a custom scanner...) by
   registering their Docker image + command there - see section 6.
2. **`/profiles`** - the seeded "Standard" profile (ClamAV only,
   `ALL_MUST_PASS`) is the default for any scan that doesn't specify one.
   Create additional profiles (e.g. "High Security") as needed.
3. **`/settings/api-clients`** - create an API client for each
   application that will call the universal upload API (see section 6.3)
   - the key is shown exactly once.
4. **`/settings/encrypted-files`** - review the default `DENY` policy per
   category and adjust if needed.

### 4.3 Bare metal alternative (both servers, no Docker on the Scanner Server either)

```bash
sudo useradd --system --shell /usr/sbin/nologin scanner
sudo mkdir -p /opt/nextcloud-upload-scanner /var/lib/nextcloud-scanner/runs \
              /var/lib/upload-scanner/staging /var/lib/upload-scanner/quarantine
sudo cp -r api ansible requirements.txt /opt/nextcloud-upload-scanner/
sudo cp .env /opt/nextcloud-upload-scanner/.env
sudo chown -R scanner:scanner /opt/nextcloud-upload-scanner /var/lib/nextcloud-scanner /var/lib/upload-scanner

# .env.example's ANSIBLE_*_PATH values default to the Docker layout
# (/app/ansible/...); point them at the copy above instead:
sudo -u scanner sed -i \
    -e 's#^ANSIBLE_FETCH_PLAYBOOK_PATH=.*#ANSIBLE_FETCH_PLAYBOOK_PATH=/opt/nextcloud-upload-scanner/ansible/fetch_from_nextcloud.yml#' \
    -e 's#^ANSIBLE_SCAN_PLAYBOOK_PATH=.*#ANSIBLE_SCAN_PLAYBOOK_PATH=/opt/nextcloud-upload-scanner/ansible/scan_uploaded_file.yml#' \
    -e 's#^ANSIBLE_DELETE_PLAYBOOK_PATH=.*#ANSIBLE_DELETE_PLAYBOOK_PATH=/opt/nextcloud-upload-scanner/ansible/delete_infected_source.yml#' \
    -e 's#^ANSIBLE_INVENTORY_PATH=.*#ANSIBLE_INVENTORY_PATH=/opt/nextcloud-upload-scanner/ansible/inventory.ini#' \
    -e 's#^ANSIBLE_CONFIG_PATH=.*#ANSIBLE_CONFIG_PATH=/opt/nextcloud-upload-scanner/ansible/ansible.cfg#' \
    /opt/nextcloud-upload-scanner/.env

sudo -u scanner python3 -m venv /opt/nextcloud-upload-scanner/venv
sudo -u scanner /opt/nextcloud-upload-scanner/venv/bin/pip install -r /opt/nextcloud-upload-scanner/requirements.txt
sudo -u scanner /opt/nextcloud-upload-scanner/venv/bin/ansible-galaxy collection install community.docker ansible.posix

# Requires a locally-installed PostgreSQL and Docker daemon; apply both migrations once, in order:
psql "$DATABASE_URL" -f /opt/nextcloud-upload-scanner/db/migrations/0001_init.sql
psql "$DATABASE_URL" -f /opt/nextcloud-upload-scanner/db/migrations/0002_platform.sql

sudo usermod -aG docker scanner    # worker needs local Docker access

sudo cp systemd/scanner-api.service systemd/scanner-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now scanner-api scanner-worker
sudo systemctl status scanner-api scanner-worker
```

---

## 5. Nextcloud integration

### 5.1 Prerequisite: the `workflow_script` app

The "Run script" Flow action is **not** built into Nextcloud core - it's
a separate app that must be installed and enabled first:

```bash
sudo -u www-data php occ app:install workflow_script   # if not already installed
sudo -u www-data php occ app:enable workflow_script
sudo -u www-data php occ app:list | grep workflow_script   # confirm "Enabled"
```

Then, in the Nextcloud admin UI under **Settings -> Flow**, add a rule:
event "File created" (or "File changed", per your needs) -> action "Run
script" -> command:

```
/usr/local/bin/nextcloud-upload-scanner.sh %f %n %a
```

**Do not wrap the placeholders in quotes** (`"%f"` etc.) - the app
already shell-quotes each substituted value itself; adding your own
quoting is actively discouraged by Nextcloud's own docs and can corrupt
argument splitting. The rule must be **enabled** and, unless you scope it
to specific folders/tags, applies to every user - Nextcloud's Flow
UI makes it easy to save a rule in a disabled or half-configured state
without any obvious warning.

- `%f` - absolute filesystem path to the file (matches `$1` / `file_path`).
- `%n` - path relative to the user's storage root (matches `$2` / `relative_path`).
- `%a` - acting username (matches `$3` / `username`).

The script now submits and then **polls** (see `SCANNER_POLL_INTERVAL` /
`SCANNER_POLL_TIMEOUT` in the config file) rather than getting an
immediate synchronous answer - configure Nextcloud's Flow "Script" check
the same way as before (exit 0 = pass, non-zero = fail -> deny/quarantine).
A poll timeout also exits 2 (ERROR) - fail closed, same as any other
error.

### 5.2 If Nextcloud itself runs in a container

**This is the single most common reason the integration silently does
nothing.** `workflow_script`'s PHP code executes the script FROM INSIDE
the Nextcloud process - if Nextcloud runs as a Docker container (official
`nextcloud` image, Nextcloud AIO, etc.), that means `/usr/local/bin/nextcloud-upload-scanner.sh`
must exist **inside that container's filesystem**, not just on the
Docker host. Installing it per section 4.1 on the host does nothing if
Nextcloud is containerized - the container can't see the host's
`/usr/local/bin` unless you explicitly put it there.

Options, simplest first:

```yaml
# In Nextcloud's own docker-compose.yml, bind-mount the script and
# config straight into the running container - no image rebuild needed:
services:
  nextcloud:
    volumes:
      - ./nextcloud-upload-scanner.sh:/usr/local/bin/nextcloud-upload-scanner.sh:ro
      - ./nextcloud-upload-scanner.conf:/etc/nextcloud-upload-scanner.conf:ro
```

Then, **inside that same container**, confirm the prerequisites the
official `nextcloud` image does NOT ship by default:

```bash
docker exec -it nextcloud sh -c "command -v curl; command -v jq; command -v sha256sum"
# any missing -> apt-get update && apt-get install -y curl jq coreutils
# (Debian-based nextcloud image) - either bake this into a custom image
# or accept it needs re-doing after every image update if installed ad hoc.

docker exec -it nextcloud mkdir -p /var/log && touch /var/log/nextcloud-upload-scanner.log
```

And `SCANNER_API_URL` in the config must be reachable **from inside the
Nextcloud container's own network namespace** - `127.0.0.1` there means
the Nextcloud container itself, never the Scanner Server, even if
they're both on the same Docker host. Use the Scanner Server's real
LAN IP/hostname (matching `config/nextcloud-upload-scanner.conf.example`'s
guidance), or a Docker network alias if both stacks share a Docker
network.

### 5.3 Debugging "nothing happens at all"

If uploading a file produces **no log entries whatsoever** (not even an
`ERROR` line) and no scan ever appears in the panel, the script itself
never started running - the problem is entirely upstream, in Nextcloud's
own invocation of it, not in the script's logic. Work through these in
order:

1. Confirm the Flow rule exists, is **enabled**, and its trigger event
   actually matches how you're testing (uploading a genuinely new file
   for "File created"; check you're not testing with a file type/folder
   the rule excludes).
2. Confirm `workflow_script` is installed AND enabled (section 5.1) -
   Nextcloud silently ignores a "Run script" rule if the app providing it
   isn't active.
3. If Nextcloud runs in Docker, confirm the script/config actually exist
   **inside the container** (section 5.2) - this is the most common cause.
4. Check Nextcloud's own log (`occ log:tail`, or Settings -> Logging in
   the admin UI) for PHP-level errors around `proc_open`/`exec` -
   hardened PHP configs (`disable_functions`) commonly block the
   process-spawning calls `workflow_script` needs entirely, which fails
   inside Nextcloud itself before this project's script ever runs.
5. Run the script **by hand**, in the exact same execution context
   Nextcloud would use (inside the container, if containerized), to see
   real output instead of guessing:
   ```bash
   docker exec -it nextcloud /usr/local/bin/nextcloud-upload-scanner.sh \
       /var/www/html/data/admin/files/test.txt files/test.txt admin
   echo "exit code: $?"
   ```
   A working invocation prints `CLEAN:`/`INFECTED:`/`ERROR:` to stdout
   and appends to the log file: if THIS works but Nextcloud's automatic
   Flow trigger still produces nothing, the bug is confirmed to be in
   Nextcloud's own Flow configuration/execution (steps 1-4), not in this
   script.

### 5.4 Integrating anything else (NFS/SMB watchers, custom apps)

There are **two different integration mechanisms** in this project -
picking the right one matters:

| | Nextcloud (`nextcloud-upload-scanner.sh`) | Everything else (`generic-file-upload-scanner.sh`) |
|---|---|---|
| What's sent over the network | A **path reference** only (JSON metadata) | The **actual file bytes** |
| Transfer of the real file | Worker fetches it separately, over SSH/SFTP | Happens as part of the same HTTP request |
| Auth | One shared `SCANNER_API_TOKEN` bearer token | A per-application **API key** from the panel |
| Endpoint | `POST /api/v1/scan` (legacy, path-reference) | `POST /api/v1/files/upload` (universal upload API) |
| Requires | The Nextcloud host in `NEXTCLOUD_HOSTS` + `ansible/inventory.ini`, SSH access | Nothing beyond an API key - works from anywhere with HTTP access to the Scanner Server |

Use `generic-file-upload-scanner.sh` for **anything that is not the
Nextcloud host itself** - an NFS/SMB share you want scanned on write, a
different application's own upload handler, a CI pipeline, etc. It
doesn't need SSH access to anything, doesn't need an `ansible/inventory.ini`
entry, and doesn't need `NEXTCLOUD_HOSTS` - it just needs an API key.

**1. Create an API key per application** in the panel, under
**Settings -> API clients -> New API client** (or `/upload` to test
manually first). Give each distinct application its own key - a share
watcher and a CI pipeline should NOT share one key, since revoking one
compromised key shouldn't require rotating everyone else's. Permissions:
`scan.upload` is required; add `scan.read` if that application also
wants to poll/read back its own scan results. Optionally pin the client
to one scanner profile so it can never be pointed at a different,
possibly less strict, profile.

**2. Install the script and its config** on whatever host will do the
scanning (the machine with access to the files - this does NOT need to
be the Scanner Server itself):

```bash
sudo install -o root -g root -m 0755 scripts/generic-file-upload-scanner.sh \
    /usr/local/bin/generic-file-upload-scanner.sh
sudo install -o root -g root -m 0600 config/file-upload-scanner.conf.example \
    /etc/file-upload-scanner.conf
sudo "${EDITOR:-nano}" /etc/file-upload-scanner.conf   # SCANNER_API_URL, API_KEY, SOURCE_APPLICATION
```

**3. Wire it up to whatever triggers a scan.** A couple of common
patterns:

```bash
# One-off / manual test:
generic-file-upload-scanner.sh /mnt/nfs-share/incoming/report.pdf someuser nfs-incoming

# Watch an NFS/SMB mount and scan every new file as it lands
# (requires inotify-tools; run this as a systemd service, not by hand):
inotifywait -m -e close_write --format '%w%f' /mnt/nfs-share/incoming | while read -r f; do
    generic-file-upload-scanner.sh "$f" "$(stat -c '%U' "$f")" nfs-incoming
    # non-zero exit ($? = 1 INFECTED, 2 ERROR) - decide here whether your
    # workflow should quarantine/delete/alert on that specific file; this
    # script only reports the verdict, it never touches the source file
    # itself (unlike the Nextcloud flow, there's no SSH-based delete step
    # here - build that on top if this integration needs it).
done
```

For a **custom application** with its own upload handling code, skip the
shell script entirely and call the API directly - see README section
8.3 for the exact `curl` request shape, or `/docs` (if `DOCS_ENABLED=true`)
for the full OpenAPI schema. The shell script is a convenience wrapper
around exactly that same HTTP call, nothing more.

---

## 6. Management panel

- `/login` - session-cookie auth, `PANEL_ADMIN_USERNAME` / the PBKDF2
  hash in `PANEL_ADMIN_PASSWORD_HASH`. Locks out after 5 failed attempts
  from the same (username, IP) pair for 15 minutes.
- `/dashboard` - total/clean/infected/error/encrypted/scanning/waiting
  counts, uploads/scans today, a 14-day clean-vs-infected chart, top
  threats, top users, scans by source, scans by antivirus.
- `/upload` - drag-and-drop a file straight from the browser for
  scanning, no API key needed - any logged-in admin already has full
  panel access. Goes through the exact same staging/hashing/encrypted-file/
  scanner-profile pipeline as `POST /api/v1/files/upload` (they share
  `routes_upload.py`'s `stream_upload_to_staging`/`finalize_staged_upload`
  helpers), tagged `source_application=panel`, `api_client_id=NULL`. Lets
  you pick a scanner profile or default to the system default, and
  optionally upload "on behalf of" a different username (defaults to
  your own). Every manual upload is recorded in `/audit` as
  `manual_upload`.
- `/scans` - full history: paginated, filterable by status, username,
  Nextcloud host, **source application, antivirus, SHA256**, and a date
  range; search matches filename, SHA256, or scan/request ID.
  Auto-refreshes every 5s via HTMX so in-flight scans visibly progress
  without a manual reload.
- `/scans/{scan_id}` - file info, user info, **one row per scanner that
  ran**, the policy section (profile, aggregation policy, encrypted
  policy, final decision + reason), pipeline sub-status, a timeline, and
  a **Re-scan** button (creates a new scan referencing this one via
  `parent_scan_id` - the original result is never modified).
- `/scanners`, `/scanners/new`, `/scanners/{id}/edit` - register/edit a
  scanner's Docker image, argument-array command, timeout, CPU/memory
  limits, and result parser. See section 6.1.
- `/profiles`, `/profiles/new`, `/profiles/{id}/edit` - group scanners
  into a named profile with an ordering and an aggregation policy.
- `/settings` - links to the four settings sub-pages below.
- `/settings/encrypted-files` - per-category ALLOW/DENY/QUARANTINE/MARK_FOR_REVIEW.
- `/settings/api-clients` - create/revoke/rotate API keys; the full key
  is shown exactly once. See section 6.3.
- `/settings/security` - retention, rate limits, max file size,
  extension/MIME allow/block lists - all DB-backed, take effect
  immediately (no restart). A few related settings
  (`MAX_CONCURRENT_SCANS`, `DOCS_ENABLED`, `RETAIN_INFECTED_COPY`) stay
  as env vars instead, since they're read once at process startup.
- `/audit` - every login, scanner/profile/API-key/encrypted-policy
  change, and manual re-scan, with actor/action filters. Never
  auto-pruned unless explicitly enabled in `/settings/security`.

Every state-changing panel form is protected by a session-bound CSRF
token (`api/panel/csrf.py`, double-submit pattern).

Scan history is never deleted when staging files are cleaned up -
`scans` is the permanent record; only the scanner-side temporary copy
(and, for infected files via the legacy path, the Nextcloud source) is
ever removed.

### 6.1 Registering a new scanner

A scanner is configuration, not code - adding one never touches
`api/scanner.py` or the Ansible playbooks. From `/scanners/new`:

- **Docker image**: e.g. `clamav/clamav:latest`, or your own image.
- **Scan command**: a JSON array (Docker exec form - never a shell
  string), e.g. `["clamscan", "--no-summary", "{{FILE}}"]`. Only
  `{{FILE}}`/`{{OUTPUT}}` placeholders and a restricted character set
  (`A-Za-z0-9_./=:,+ -`) are accepted - see `api/scanners.py::validate_scan_command`.
  This is enforced at save time (admin-only) AND the command is still
  only ever passed as an argv list to Docker, never through a shell.
- **Result parser**: `clamav_wrapper_json` if the image's entrypoint
  writes our canonical `result.json` contract (see `docker/scan.sh` for
  the reference implementation - copy this pattern for a new scanner
  that needs to report CLEAN/INFECTED/ERROR with a threat name).
  `generic_exit_code` for any other image - honest limitation: exit
  0 -> CLEAN, anything else -> ERROR, and it **can never report
  INFECTED** (no way to know why a process exited non-zero without a
  wrapper). Ship a small wrapper script if you need real detection
  reporting from a stock upstream image.
- **Timeout / CPU limit / memory limit**: enforced per-container by
  `community.docker.docker_container` (`timeout`, `cpus`, `memory`) - see
  `ansible/tasks/run_one_scanner.yml`.

### 6.2 Scanner profiles and aggregation policy

A profile is an ordered set of scanners plus one `aggregation_policy`:

| Policy | Detection | Scanner error |
|---|---|---|
| `ALL_MUST_PASS` (default) | any detection -> INFECTED | any error -> ERROR (blocks) |
| `ANY_DETECTION` | any detection -> INFECTED | tolerated if >=1 other scanner is CLEAN |
| `FIRST_DETECTION` | first scanner (profile order) to detect wins | blocks unless a later scanner still detects |
| `FIRST_SUCCESS` | first scanner (profile order) to complete (CLEAN or INFECTED) decides, skipping errored ones | - |

Every individual scanner's result is stored in `scan_results` regardless
of policy - the aggregation only decides the final verdict, it never
discards evidence.

### 6.3 API clients and scoping

Each client has `permissions` (`scan.upload`, `scan.read` - own scans
only, `scan.read_all` - any client's scans) and an optional
`scanner_profile_id`. If pinned, that client can NEVER use a different
profile (`POST /api/v1/files/upload` with a mismatched `profile` field
returns `403`) - the server decides, not the caller. If unpinned, the
client may specify any enabled profile's slug, or omit it to get the
system default. Keys are generated as `sk_live_<32 random bytes,
url-safe>`, stored only as a SHA-256 hash (`api/auth_apikey.py`) - the
plaintext key is shown exactly once, at creation or rotation.

---

## 7. Security summary

| Control | Where |
|---|---|
| Bearer token auth (legacy `/api/v1/scan`), `hmac.compare_digest`, never logged | `api/security.py`, `api/main.py` |
| API key auth (universal upload API): SHA-256 hash at rest, never plaintext, shown once | `api/auth_apikey.py` |
| API permission scoping (`scan.upload`/`scan.read`/`scan.read_all`) + ownership checks (404, not 403, for scans you don't own) | `api/auth_apikey.py::require_permission`, `api/routes_upload.py::_get_scan_with_ownership_check` |
| API client pinned to a scanner profile cannot request a different one | `api/routes_upload.py::_resolve_profile_for_client` |
| Per-host path allowlist (`NEXTCLOUD_HOSTS[x].allowed_root`) | `api/security.py`, `ansible/fetch_from_nextcloud.yml` |
| Authoritative `realpath` + symlink check, on the Nextcloud host itself | `ansible/fetch_from_nextcloud.yml` |
| Host allowlist - client selects a key only, never ansible_host/user/inventory | `api/security.py::resolve_nextcloud_host` |
| No arbitrary Ansible extra-vars from the HTTP request | `api/ansible_runner.py` - extra-vars built server-side only |
| `subprocess.run([...])`, never `shell=True` | `api/ansible_runner.py` |
| Scanner commands: admin-only, strict argument-array validation, never a shell string | `api/scanners.py::validate_scan_command` |
| SHA256 verification at every hop: client/upload claim -> Nextcloud actual -> transferred actual -> scanned actual | `ansible/fetch_from_nextcloud.yml`, `ansible/scan_uploaded_file.yml`, `api/scanner.py` |
| Docker runs ONLY on the Scanner Server; scan containers never mount Nextcloud's filesystem | `ansible/tasks/run_one_scanner.yml` |
| `api` container has no Docker socket and no SSH key (except the staging volume, for direct uploads); only `worker` has both | `docker-compose.yml` |
| TOCTOU-safe infected-file deletion: re-stat, re-hash, compare to the SCANNED hash, abort on any mismatch | `ansible/delete_infected_source.yml` |
| Deletion happens only after the INFECTED verdict + its hash are durably in PostgreSQL | `api/scanner.py::process_scan` |
| Every scan gets a permanent DB record; only staging files are deleted, never the record | `api/db.py`, `db/migrations/` |
| Fail-closed on any scanner/transfer/DB/encryption-detection error | `api/scanner.py`, `api/worker.py`, `api/policy.py` |
| Concurrent uploads: `FOR UPDATE SKIP LOCKED` job claiming, isolated per-scan-id staging dirs | `api/db.py::claim_next_scan` |
| Container: no privileged, cap_drop ALL, read-only rootfs, non-root, network_mode none, per-scanner CPU/memory/timeout limits | `ansible/tasks/run_one_scanner.yml` |
| Panel auth: PBKDF2-HMAC-SHA256 password hash, signed session cookie, login lockout | `api/panel/auth.py` |
| CSRF protection on every state-changing panel form | `api/panel/csrf.py` |
| CORS strict by default (empty allowlist), request body size capped | `api/main.py` |
| Rate limiting: general (`api/main.py`) and upload-specific, DB-configurable | `api/main.py::RateLimiter`, `api/routes_upload.py::_upload_rate_limit_ok` |
| File type policy: optional extension/MIME allow/block lists, never the sole control | `api/routes_upload.py::_check_file_type_policy` |
| Encrypted-file policy: skips scanning, decided by explicit per-category configuration, defaults to DENY | `api/encryption_detect.py`, `api/policy.py` |
| Staging directories: per-scan UUID, restrictive permissions, never under `/tmp`, max-lifetime sweep | `api/scanner.py`, `api/worker.py::_sweep_stale` |
| Audit log: every admin/security-relevant action recorded, never auto-pruned by default | `api/db.py::record_audit`, `db/migrations/0002_platform.sql` |
| `/docs`/`/redoc` can be disabled entirely (`DOCS_ENABLED=false`) | `api/main.py` |

---

## 8. Testing

### 8.1 Unit tests (no PostgreSQL/Docker/Ansible required)

```bash
pip install -r requirements.txt
pytest tests/ -v
```

These mock `db.*` and `ansible_runner.run_playbook`, so they validate
the API/worker's own logic (auth, per-host path/host allowlisting, size
limits, the three-way sha256 checks, the TOCTOU-abort-never-changes-verdict
invariant, panel auth) without needing a live Scanner/Nextcloud pair.

### 8.2 End-to-end scenarios

Assumes both servers are up, `.env` and `ansible/inventory.ini` point at
your real hosts, and `SCAN_ID` capturing works via `jq`.

**Test 1 - clean file**: upload a plain text file. Expect: panel shows
`CLEAN`, `allowed=true`; the original stays on the Nextcloud server; the
Scanner Server's staging directory for that scan is gone.

**Test 2 - EICAR test file** (the standard, harmless antivirus test
string - not real malware):
```bash
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
    > /var/www/nextcloud/data/admin/files/eicar.txt
```
Expect: panel shows `INFECTED`, `allowed=false`, threat
`Eicar-Test-Signature`; the ORIGINAL file on the Nextcloud server is
deleted; the Scanner Server's staging directory is gone.

**Test 3 - source file does not exist**: submit a `file_path` that was
never actually written. Expect: `ERROR`, no Docker scan ever runs
(`scan_status_detail=SKIPPED`).

**Test 4 - path traversal**: submit `file_path=/etc/passwd` or anything
containing `..`. Expect: synchronous `403` from `POST /api/v1/scan`
itself - no `scan_id`, no database row, no file transfer ever attempted.

**Test 5 - SHA256 mismatch**: POST with a `sha256` that doesn't match
the real file. Expect: `ERROR`, and critically - nothing is deleted
anywhere (verify the source file is untouched on the Nextcloud server).

**Test 6 - ClamAV/Scanner Server unavailable**: stop the `worker` (or
`freshclam-updater`/Docker) and submit a scan. Expect: `ERROR`,
`allowed=false`; the original file remains on the Nextcloud server
(deletion never happens for a non-INFECTED result, by construction - see
`api/scanner.py::process_scan`).

**Test 7 - two simultaneous uploads**: fire two uploads at once (`&` in
bash, or two terminals). Expect: two distinct `scan_id`s, two isolated
staging directories under `STAGING_BASE`, no file collision - this is
what `db.py::claim_next_scan`'s `FOR UPDATE SKIP LOCKED` guarantees.

**Test 8 - large file**: upload a file near `MAX_FILE_SIZE`. Expect:
either a clean rejection (`413`/`400`, no transfer attempted for
oversized files) or a normal scan - never a worker crash or unbounded
memory growth (the worker streams nothing into memory; ClamAV and SFTP
both operate on the file on disk).

### 8.3 Universal upload API - end-to-end scenarios

**IMPORTANT: unverified in this build.** Everything below was written
against the actual code paths and is believed correct, but there was no
live Docker/PostgreSQL/Scanner Server available while building this -
see CLAUDE.md's build-status section. Run these for real before trusting
the platform in production.

Setup: create an API client at `/settings/api-clients` (permissions
`scan.upload` + `scan.read`; leave scanner profile unpinned for tests 3
and 9) and export its key:

```bash
export API_KEY="sk_live_..."
export BASE="https://scanner.example.com"
```

**1. Clean file:**
```bash
echo "hello world" > clean.txt
curl -s -X POST "$BASE/api/v1/files/upload" \
    -H "Authorization: Bearer $API_KEY" \
    -F "file=@clean.txt" -F "username=mohammad" -F "source=e2e-test"
# {"scan_id": "...", "status": "QUEUED", "message": "File accepted for scanning"}

SCAN_ID=<paste scan_id>
curl -s "$BASE/api/v1/scans/$SCAN_ID" -H "Authorization: Bearer $API_KEY"
# {"scan_id":"...","status":"CLEAN","allowed":true,"filename":"clean.txt",
#  "sha256":"...","scanners":[{"name":"ClamAV","status":"CLEAN","threat":null}]}
```

**2. EICAR infected file:**
```bash
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.txt
curl -s -X POST "$BASE/api/v1/files/upload" \
    -H "Authorization: Bearer $API_KEY" \
    -F "file=@eicar.txt" -F "username=mohammad" \
    "$BASE/api/v1/files/upload?wait=true&timeout=30"
# Expect (synchronous - the API waits server-side up to 30s):
# {"scan_id":"...","status":"INFECTED","allowed":false,"filename":"eicar.txt",
#  "sha256":"...","threats":["Eicar-Test-Signature"],"scanners":[...]}
```

**3. Multiple scanners:** create a "High Security" profile at `/profiles`
with ClamAV + a second registered scanner, `aggregation_policy=ALL_MUST_PASS`:
```bash
curl -s -X POST "$BASE/api/v1/files/upload" \
    -H "Authorization: Bearer $API_KEY" \
    -F "file=@clean.txt" -F "username=mohammad" -F "profile=high-security"
curl -s "$BASE/api/v1/scans/$SCAN_ID/results" -H "Authorization: Bearer $API_KEY"
# {"scan_id":"...","results":[{"scanner":"ClamAV","status":"CLEAN",...},
#                              {"scanner":"<second scanner>","status":"CLEAN",...}]}
```

**4. Scanner failure:** temporarily set a scanner's `docker_image` to a
nonexistent tag at `/scanners/{id}/edit` (or stop the worker's Docker
daemon), then upload. Expect: `status: ERROR`, `allowed: false`; check
`/scans/{scan_id}` shows that scanner's individual result as `ERROR`
too, and (under `ALL_MUST_PASS`) the overall verdict is `ERROR` even if
every OTHER scanner in the profile reported clean.

**5. Encrypted file:**
```bash
zip -e --password s3cret encrypted.zip clean.txt
curl -s -X POST "$BASE/api/v1/files/upload" \
    -H "Authorization: Bearer $API_KEY" \
    -F "file=@encrypted.zip" -F "username=mohammad" \
    "$BASE/api/v1/files/upload?wait=true"
# {"scan_id":"...","status":"ENCRYPTED","allowed":false}   (default policy = DENY)
```
Change `/settings/encrypted-files`'s "Password-protected archive" policy
to `ALLOW` and repeat - expect `"allowed": true` while `status` still
correctly reports `ENCRYPTED` (no scanner can actually inspect it).

**6. Unknown encryption:** upload a `.rar` or `.7z` file (best-effort
detection can't determine RAR/7z password state - see section 1b).
Expect `/scans/{scan_id}` shows `encrypted: null` (unknown),
`encryption_type` set to the container type, and the `unknown_encryption`
category's policy applied - not silently treated as safe to scan.

**7. API key revoked:**
```bash
# In the panel: /settings/api-clients -> Revoke on this client
curl -s -o /dev/null -w "%{http_code}\n" -X POST "$BASE/api/v1/files/upload" \
    -H "Authorization: Bearer $API_KEY" -F "file=@clean.txt" -F "username=mohammad"
# 401
```

**8. User filtering:** upload as two different usernames, then in the
panel go to `/scans?username=mohammad` - expect only that user's scans;
`/scans?source=e2e-test` filters by the `source` field similarly. Top
Users on `/dashboard` should reflect both.

**9. Scanner profile selection:** upload once with no `profile` field
(uses the client's pinned profile, or the system default), once with
`-F "profile=high-security"` on an UNPINNED client (allowed), and once
requesting a profile on a client that IS pinned to a different one -
expect `403` for the last case (see section 6.3).

**10. Re-scan:** open any completed scan's detail page and click
**Re-scan**. Expect: a NEW `scan_id`, the original scan's row completely
unchanged, and the new scan's detail page shows "This is a re-scan of
`<original id>`" with a working link back.

---

## 9. Troubleshooting

```bash
# API / worker logs
docker logs -f nextcloud-scanner-api
docker logs -f nextcloud-scanner-worker

# PostgreSQL
docker exec -it nextcloud-scanner-postgres psql -U scanner -d scanner -c \
    "SELECT id, status, filename, nextcloud_host, created_at FROM scans ORDER BY created_at DESC LIMIT 10;"

# Confirm the playbooks/inventory actually landed in the image (baked in,
# not bind-mounted - see CLAUDE.md incident log)
docker exec nextcloud-scanner-worker ls -la /app/ansible

# Confirm Ansible collections are visible to the worker's runtime user
docker exec nextcloud-scanner-worker ansible-galaxy collection list

# Confirm the worker can reach docker.sock
docker exec nextcloud-scanner-worker docker info

# SSH connectivity from the Scanner Server to the Nextcloud Server
docker exec nextcloud-scanner-worker ssh -i /home/scanner/.ssh/id_ed25519 scanner_svc@<nextcloud-ip> 'echo ok'

# Run the scan playbook by hand for full -vvv output
docker exec -it nextcloud-scanner-worker sh -c '
  ANSIBLE_CONFIG=/app/ansible/ansible.cfg ansible-playbook \
    -i /app/ansible/inventory.ini /app/ansible/scan_pipeline.yml \
    --limit "nextcloud01,scanner" -vvv \
    -e request_id=manual-test \
    -e nextcloud_inventory_host=nextcloud01 \
    -e file_path=/var/www/nextcloud/data/admin/files/test.txt \
    -e expected_sha256=$(ssh scanner_svc@<nextcloud-ip> sha256sum /var/www/nextcloud/data/admin/files/test.txt | cut -d" " -f1) \
    -e expected_size=100 -e max_file_size=5368709120 \
    -e allowed_root=/var/www/nextcloud/data \
    -e staging_dir=/tmp/manual-staging \
    -e docker_scan_image=nextcloud-scanner-clamav:latest \
    -e clamav_timeout=120 -e result_file=/tmp/manual-result.json
'
```

Common failure modes:

- **`POST /api/v1/scan` returns 403 "Host is not permitted"** - the
  hostname the Bash script reports doesn't match a key in `.env`'s
  `NEXTCLOUD_HOSTS`, or that key has no matching entry in
  `ansible/inventory.ini`'s `[nextcloud]` group.
- **Stuck at `TRANSFERRING`/`SCANNING` forever** - the worker isn't
  running, or crashed; `docker logs nextcloud-scanner-worker`.
  `STAGING_MAX_LIFETIME_SECONDS` eventually force-fails it (default 1h) -
  lower this for faster feedback while debugging.
- **`Could not match supplied host pattern`** - the `--limit` pattern
  didn't match; check the exact hostname in both `NEXTCLOUD_HOSTS` and
  `inventory.ini`'s `[nextcloud]` group match, and that `[scanner]`
  still has exactly one host (`scan_pipeline.yml`'s Play 2 needs it).
- **`couldn't resolve module/action 'community.docker.docker_container'`** -
  check `docker exec nextcloud-scanner-worker ls -la /usr/share/ansible/collections/ansible_collections`
  shows `community/docker`; rebuild if not.
- **Worker can't reach `/var/run/docker.sock`** (scan errors with
  `Error connecting: ... PermissionError(13, 'Permission denied')` in
  `scan_results.raw_output` for every scanner) - `DOCKER_GID` in `.env`
  doesn't match the actual GID that owns the socket. `getent group docker`
  on the host is UNRELIABLE for this on Docker Desktop (Windows/Mac) -
  the daemon runs inside its own VM, so the host's own group table often
  doesn't reflect it. Ask the daemon directly instead:
  ```bash
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock alpine stat -c '%g' /var/run/docker.sock
  ```
  Set `DOCKER_GID` to whatever number that prints, then
  `docker compose up -d worker` (`group_add` is a container-creation-time
  setting - recreating the container picks it up; no image rebuild
  needed, unlike most other `.env`/`docker-compose.yml` changes in this
  list). Verify with `docker compose exec worker id` - the GID should
  appear in the `groups=` list.
- **Panel login always fails** - `PANEL_ADMIN_PASSWORD_HASH` wasn't
  actually generated with `panel.auth.hash_password` (see section 4.2),
  or `.env` wasn't reloaded (`docker compose up -d --build` after
  editing).
- **Panel login redirects back to itself over HTTPS-fronted setups** -
  check `PANEL_SESSION_COOKIE_SECURE` is `true` only when actually served
  over HTTPS (via a reverse proxy) - a `Secure` cookie is silently
  dropped by browsers over plain HTTP.
- **Result stuck at ERROR with a checksum-ish message** - freshclam
  hasn't produced a database yet on a fresh install; wait for the first
  `freshclam-updater` cycle or `docker exec nextcloud-scanner-freshclam freshclam`.
- **ClamAV result shows `find: '/scan/input': No such file or directory`
  / `cannot create /scan/output/result.json: Directory nonexistent`** -
  your locally-built `nextcloud-scanner-clamav:latest` image is stale,
  built from an older `docker/scan.sh` that used the pre-platform-layer
  mount layout (`/scan/input` + `/scan/output`, changed to plain `/scan`
  + `/output` - see CLAUDE.md's design-decision notes). This image is
  NOT one of the `docker-compose.yml` services, so `docker compose up -d
  --build` never rebuilds it - it has to be rebuilt explicitly:
  ```bash
  docker build -t nextcloud-scanner-clamav:latest -f docker/Dockerfile docker/
  ```
  No restart needed afterward - each scan starts a fresh ephemeral
  container from whatever image currently has that tag, so the next
  upload picks up the rebuild automatically.

### 9.1 Platform-layer issues

```bash
# Confirm both migrations actually applied (fresh installs run these
# automatically via docker-entrypoint-initdb.d - see section 4.2; this
# is only needed on an upgrade of an EXISTING database)
docker exec -it nextcloud-scanner-postgres psql -U scanner -d scanner -f /dev/stdin < db/migrations/0002_platform.sql
docker exec -it nextcloud-scanner-postgres psql -U scanner -d scanner -c "\d scanners"

# List registered scanners/profiles from the DB directly
docker exec -it nextcloud-scanner-postgres psql -U scanner -d scanner -c \
    "SELECT slug, enabled, docker_image FROM scanners;"
docker exec -it nextcloud-scanner-postgres psql -U scanner -d scanner -c \
    "SELECT slug, aggregation_policy, is_default FROM scanner_profiles;"

# Preview exactly what command Ansible will run for a given scanner
# without actually scanning anything (uses the same render_command_preview()
# the panel's scanner form calls when you click "Preview command")
docker exec nextcloud-scanner-api python3 -c \
    "from scanners import render_command_preview; print(render_command_preview(['clamscan','{{FILE}}','-o','{{OUTPUT}}'], '/scan/test.pdf', '/output'))"
```

Common platform-specific failure modes:

- **`postgres` crash-loops with `ls: can't open '/docker-entrypoint-initdb.d/':
  Permission denied`** - this is a Windows/Docker Desktop bind-mount
  reliability issue (the same class of problem `ansible/` hit once
  before - see CLAUDE.md's incident log), fixed by baking
  `db/migrations/` into the `postgres` image at build time instead of
  bind-mounting it. If you still see this, you're on a version of this
  repo from before that fix - `git pull`/re-copy the latest
  `docker-compose.yml` and `db/Dockerfile`, then:
  ```bash
  docker compose down
  docker volume rm postgres_data
  docker compose up -d --build
  docker compose logs -f postgres
  ```
  **Only run `docker volume rm postgres_data` on a deployment that never
  had real scan history** - `initdb` runs before the init-scripts step,
  so a crash at this point still leaves a non-empty, half-initialized
  data directory behind; simply fixing the mount and restarting will NOT
  retroactively run the migrations against it, since Postgres only ever
  processes `/docker-entrypoint-initdb.d/` against a genuinely fresh,
  empty data directory. If in doubt, check for existing data first:
  `docker exec nextcloud-scanner-postgres psql -U scanner -d scanner -c "SELECT count(*) FROM scans;"`.
- **`0002_platform.sql` fails with `type "scan_status" already has value
  "ENCRYPTED"`** - the migration was already applied (its `ALTER TYPE ...
  ADD VALUE IF NOT EXISTS` should make re-running safe, but the enum
  additions in older PostgreSQL (<12) don't support `IF NOT EXISTS` at
  all - if you're on <12, this is expected on a second run and can be
  ignored; upgrade PostgreSQL if you need real idempotency here).
- **`POST /api/v1/files/upload` returns 401 with a syntactically valid
  key** - `api_clients.enabled` is `false`, or the key was hashed with a
  different `hash_api_key()` implementation than the one the DB row was
  created with (only relevant if you're re-seeding clients by hand
  rather than through `/settings/api-clients`, which always uses the
  live code path).
- **`POST /api/v1/files/upload` returns 403 "profile not permitted"** -
  the API client is pinned to a specific `scanner_profile_id`
  (section 6.3) and the request's `profile` field asked for a different
  one; either omit `profile` or unpin the client.
- **Scanner registered in the panel but every scan using it comes back
  `ERROR`** - check `render_command_preview` above actually produces the
  command you expect, then `docker exec nextcloud-scanner-worker ansible-playbook
  ... /app/ansible/scan_uploaded_file.yml -vvv` to see that specific
  scanner's `docker_container` task output; a scanner whose
  `docker_image` was never pulled on the Scanner Server will fail exactly
  this way, not with a clearer "image not found" surfaced to the API
  client (fail-closed by design - see section 1b).
- **A scanner profile with `ALL_MUST_PASS` blocks files that every
  configured scanner reports CLEAN on** - one scanner in the profile is
  erroring silently; check `GET /api/v1/scans/{id}/results` (or the scan
  detail page) for a per-scanner `ERROR` row, not just the aggregate
  status. This is the documented, intentional difference from
  `ANY_DETECTION` (section 1b) - not a bug.
- **Encrypted files are always DENYing even after changing the panel
  setting** - `encrypted_file_policies` is keyed by category
  (`pdf_encrypted`, `office_encrypted`, `zip_encrypted`,
  `unknown_encryption`, `default`); confirm you edited the row for the
  category the file actually matched (check `encryption_type` on the
  scan detail page), not just `default`.
- **A `.rar`/`.7z`/legacy `.doc` upload is always categorized
  `unknown_encryption` even though it isn't password-protected** - this
  is expected, not a bug; `api/encryption_detect.py` deliberately never
  claims a confident "not encrypted" for formats it can't actually
  parse (section 1b) - set that category's policy to `ALLOW` if your
  environment doesn't need to be conservative about it.
- **Re-scan button does nothing / 403** - `/scans/{id}/rescan` requires
  an authenticated panel session with a valid CSRF token
  (`csrf_token_for` global); if you're calling it directly rather than
  through the rendered button, you need a fresh token from the page,
  not a hardcoded one.
- **`/scanners` or `/profiles` public API endpoints leak `docker_image`
  or `scan_command`** - they shouldn't; if you see internal config in
  that response, check you're hitting `/api/v1/scanners` (the
  intentionally minimal universal-API endpoint), not an admin panel
  route being accidentally exposed without auth.
