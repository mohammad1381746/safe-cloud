#!/usr/bin/env bash
#
# nextcloud-upload-scanner.sh
#
# Called by Nextcloud's "Flow / Workflow Script" mechanism after a file is
# created. Submits the file's location and metadata to the Scanner API,
# then POLLS for the result - the scan itself runs asynchronously on a
# separate Scanner Server (transfer + ClamAV can take longer than a
# workflow hook should block synchronously on a single HTTP call).
#
# Usage:
#   nextcloud-upload-scanner.sh <file_path> <relative_path> <username>
#
# Exit codes:
#   0 = CLEAN      (allowed)
#   1 = INFECTED   (denied)
#   2 = ERROR       (scanner/API error, or poll timeout - treat as denied; fail closed)
#
# Configuration is read from an external file (default
# /etc/nextcloud-upload-scanner.conf, mode 600, owner root:root) so that no
# secret ever appears in this script, in `ps`, or in Nextcloud's own logs.

set -uo pipefail

SCRIPT_NAME="$(basename "$0")"
CONFIG_FILE="${SCANNER_CONFIG_FILE:-/etc/nextcloud-upload-scanner.conf}"
LOG_FILE="${SCANNER_LOG_FILE:-/var/log/nextcloud-upload-scanner.log}"

# Defaults - overridden by CONFIG_FILE.
SCANNER_API_URL="http://127.0.0.1:8000"
SCANNER_API_TOKEN=""
SCANNER_HOSTNAME_OVERRIDE=""
SCANNER_CURL_TIMEOUT=30
SCANNER_CONNECT_TIMEOUT=5
SCANNER_POLL_INTERVAL=3
SCANNER_POLL_TIMEOUT=180

log() {
    local level="$1"; shift
    printf '%s [%s] [pid:%d] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$level" "$$" "$*" \
        >> "$LOG_FILE" 2>/dev/null || true
}

fail_error() {
    log "ERROR" "$1"
    echo "ERROR: $1" >&2
    exit 2
}

# --- load configuration -----------------------------------------------------
if [[ -f "$CONFIG_FILE" ]]; then
    perms="$(stat -c '%a' "$CONFIG_FILE" 2>/dev/null || echo "")"
    if [[ -n "$perms" && "$perms" != "600" && "$perms" != "400" ]]; then
        log "WARN" "Config file $CONFIG_FILE has insecure permissions ($perms); expected 600"
    fi
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
else
    fail_error "Config file not found: $CONFIG_FILE"
fi

[[ -n "$SCANNER_API_TOKEN" ]] || fail_error "SCANNER_API_TOKEN is not set in $CONFIG_FILE"
[[ -n "$SCANNER_API_URL" ]] || fail_error "SCANNER_API_URL is not set in $CONFIG_FILE"

# --- argument validation -----------------------------------------------------
if [[ $# -ne 3 ]]; then
    fail_error "Usage: $SCRIPT_NAME <file_path> <relative_path> <username>"
fi

FILE_PATH="$1"
RELATIVE_PATH="$2"
USERNAME="$3"

[[ -e "$FILE_PATH" ]] || fail_error "File does not exist: $FILE_PATH"
[[ -f "$FILE_PATH" ]] || fail_error "Not a regular file: $FILE_PATH"
[[ -r "$FILE_PATH" ]] || fail_error "File not readable: $FILE_PATH"

command -v curl >/dev/null 2>&1 || fail_error "curl is required but not installed"
command -v jq   >/dev/null 2>&1 || fail_error "jq is required but not installed"
command -v sha256sum >/dev/null 2>&1 || fail_error "sha256sum is required but not installed"

# --- collect metadata ---------------------------------------------------------
HOSTNAME_VALUE="${SCANNER_HOSTNAME_OVERRIDE:-$(hostname -f 2>/dev/null || hostname)}"

FILE_SIZE="$(stat -c '%s' "$FILE_PATH" 2>/dev/null)" || fail_error "Failed to stat file: $FILE_PATH"

SHA256_HASH="$(sha256sum "$FILE_PATH" 2>/dev/null | awk '{print $1}')" \
    || fail_error "Failed to compute sha256 for: $FILE_PATH"
[[ -n "$SHA256_HASH" ]] || fail_error "Empty sha256 result for: $FILE_PATH"

PAYLOAD="$(jq -n \
    --arg file_path "$FILE_PATH" \
    --arg relative_path "$RELATIVE_PATH" \
    --arg username "$USERNAME" \
    --arg hostname "$HOSTNAME_VALUE" \
    --arg sha256 "$SHA256_HASH" \
    --argjson size "$FILE_SIZE" \
    '{file_path: $file_path, relative_path: $relative_path, username: $username,
      hostname: $hostname, sha256: $sha256, size: $size}')" \
    || fail_error "Failed to build JSON payload"

log "INFO" "Submitting scan request file=$FILE_PATH user=$USERNAME host=$HOSTNAME_VALUE sha256=$SHA256_HASH size=$FILE_SIZE"

# --- submit to the scanner API (returns 202 + scan_id, or a synchronous rejection) ---
HTTP_BODY_FILE="$(mktemp)"
trap 'rm -f "$HTTP_BODY_FILE"' EXIT

# NOTE: the token is passed only via the -H header argument to curl, never
# echoed, never placed in $PAYLOAD, and never written to $LOG_FILE.
HTTP_CODE="$(curl -sS -o "$HTTP_BODY_FILE" -w '%{http_code}' \
    --connect-timeout "$SCANNER_CONNECT_TIMEOUT" \
    --max-time "$SCANNER_CURL_TIMEOUT" \
    -X POST "${SCANNER_API_URL%/}/api/v1/scan" \
    -H "Authorization: Bearer ${SCANNER_API_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD")"
CURL_EXIT=$?

if [[ $CURL_EXIT -ne 0 ]]; then
    log "ERROR" "curl request failed with exit code $CURL_EXIT (network/timeout unreachable)"
    echo "ERROR: unable to reach scanner API"
    exit 2
fi

RESPONSE_BODY="$(cat "$HTTP_BODY_FILE")"
log "INFO" "POST /api/v1/scan responded http_code=$HTTP_CODE"

if [[ "$HTTP_CODE" != "202" ]]; then
    # Synchronous rejection - bad auth, bad host, bad path, oversized
    # file, rate limited, etc. No scan_id was ever created.
    MESSAGE="$(echo "$RESPONSE_BODY" | jq -r '.message // "unknown error"' 2>/dev/null)"
    log "ERROR" "Scan request rejected http_code=$HTTP_CODE message=$MESSAGE"
    echo "ERROR: $MESSAGE"
    exit 2
fi

SCAN_ID="$(echo "$RESPONSE_BODY" | jq -r '.scan_id // empty' 2>/dev/null)"
if [[ -z "$SCAN_ID" ]]; then
    fail_error "API accepted the request but returned no scan_id"
fi

log "INFO" "Scan queued scan_id=$SCAN_ID - polling every ${SCANNER_POLL_INTERVAL}s, timeout ${SCANNER_POLL_TIMEOUT}s"

# --- poll for the result -----------------------------------------------------
DEADLINE=$(( $(date +%s) + SCANNER_POLL_TIMEOUT ))

while true; do
    if (( $(date +%s) >= DEADLINE )); then
        log "ERROR" "Timed out after ${SCANNER_POLL_TIMEOUT}s waiting for scan_id=$SCAN_ID"
        echo "ERROR: timed out waiting for scan result"
        exit 2
    fi

    POLL_BODY_FILE="$(mktemp)"
    POLL_HTTP_CODE="$(curl -sS -o "$POLL_BODY_FILE" -w '%{http_code}' \
        --connect-timeout "$SCANNER_CONNECT_TIMEOUT" \
        --max-time "$SCANNER_CURL_TIMEOUT" \
        -X GET "${SCANNER_API_URL%/}/api/v1/scan/${SCAN_ID}" \
        -H "Authorization: Bearer ${SCANNER_API_TOKEN}")"
    POLL_CURL_EXIT=$?
    POLL_BODY="$(cat "$POLL_BODY_FILE")"
    rm -f "$POLL_BODY_FILE"

    if [[ $POLL_CURL_EXIT -ne 0 ]]; then
        log "WARN" "Poll request failed (curl exit $POLL_CURL_EXIT), retrying"
        sleep "$SCANNER_POLL_INTERVAL"
        continue
    fi

    if [[ "$POLL_HTTP_CODE" != "200" ]]; then
        log "WARN" "Poll returned http_code=$POLL_HTTP_CODE, retrying"
        sleep "$SCANNER_POLL_INTERVAL"
        continue
    fi

    STATUS="$(echo "$POLL_BODY" | jq -r '.status // "ERROR"' 2>/dev/null)"

    case "$STATUS" in
        CLEAN)
            log "INFO" "Scan CLEAN scan_id=$SCAN_ID file=$FILE_PATH sha256=$SHA256_HASH"
            echo "CLEAN: no malware detected"
            exit 0
            ;;
        INFECTED)
            THREAT="$(echo "$POLL_BODY" | jq -r '.threat // "unknown"' 2>/dev/null)"
            log "WARN" "Scan INFECTED scan_id=$SCAN_ID file=$FILE_PATH sha256=$SHA256_HASH threat=$THREAT"
            echo "INFECTED: $THREAT"
            exit 1
            ;;
        ERROR|CLEANUP_FAILED)
            MESSAGE="$(echo "$POLL_BODY" | jq -r '.message // "scan failed"' 2>/dev/null)"
            log "ERROR" "Scan ERROR scan_id=$SCAN_ID message=$MESSAGE"
            echo "ERROR: $MESSAGE"
            exit 2
            ;;
        RECEIVED|VALIDATING|TRANSFERRING|SCANNING)
            # Still in progress - keep polling.
            ;;
        *)
            log "WARN" "Unexpected status '$STATUS' for scan_id=$SCAN_ID, retrying"
            ;;
    esac

    sleep "$SCANNER_POLL_INTERVAL"
done
