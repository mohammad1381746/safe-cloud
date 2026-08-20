#!/usr/bin/env bash
#
# generic-file-upload-scanner.sh
#
# Reusable scan client for ANY application/watcher with a local file to
# check - NFS/SMB share watchers (inotifywait, a cron sweep, Samba VFS
# hooks), custom upload handlers, CI pipelines, etc. Unlike
# nextcloud-upload-scanner.sh (which only ever sends a PATH REFERENCE and
# relies on the worker fetching the file over SSH from the Nextcloud
# host), this script uploads the FILE'S ACTUAL BYTES straight to the
# universal upload API (POST /api/v1/files/upload) over HTTPS/HTTP,
# authenticated with a per-application API key from the panel
# (Settings -> API clients) - use this for anything that ISN'T the
# Nextcloud host itself.
#
# Usage:
#   generic-file-upload-scanner.sh <file_path> [username] [source_label]
#
# <file_path>    required - local path to the file to scan.
# [username]     optional - who this file belongs to; defaults to the
#                 config's DEFAULT_USERNAME, then to this script's own
#                 OS user if that's unset either.
# [source_label] optional - overrides the config's SOURCE_APPLICATION for
#                 this one call (e.g. pass the specific share/mount name).
#
# Exit codes (same convention as nextcloud-upload-scanner.sh):
#   0 = CLEAN      (allowed)
#   1 = INFECTED   (denied)
#   2 = ERROR       (scanner/API error, encrypted-and-denied, or timeout -
#                    treat as denied; fail closed)
#
# Configuration is read from an external file (default
# /etc/file-upload-scanner.conf, mode 600, owner root:root) so the API
# key never appears in this script, in `ps`, or in any watcher's own logs.

set -uo pipefail

SCRIPT_NAME="$(basename "$0")"
CONFIG_FILE="${SCANNER_CONFIG_FILE:-/etc/file-upload-scanner.conf}"
LOG_FILE="${SCANNER_LOG_FILE:-/var/log/file-upload-scanner.log}"

# Defaults - overridden by CONFIG_FILE.
SCANNER_API_URL="http://127.0.0.1:8000"
API_KEY=""
SCANNER_PROFILE=""
SOURCE_APPLICATION="generic"
DEFAULT_USERNAME=""
SCANNER_CURL_TIMEOUT=30
SCANNER_CONNECT_TIMEOUT=5
# Server-side synchronous wait (?wait=true&timeout=N) - capped by the
# API's own SYNC_WAIT_MAX_TIMEOUT_SECONDS regardless of what's asked for
# here. For files/scanners that routinely take longer than that cap,
# raise EXTRA_POLL_TIMEOUT below instead of this value.
SYNC_WAIT_TIMEOUT=60
# If the server-side wait above returns a still-in-progress result (its
# own cap was hit before the scan finished), keep polling GET
# /api/v1/scans/{id} client-side for up to this many more seconds before
# giving up and failing closed.
EXTRA_POLL_TIMEOUT=120
EXTRA_POLL_INTERVAL=3

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

[[ -n "$API_KEY" ]] || fail_error "API_KEY is not set in $CONFIG_FILE"
[[ -n "$SCANNER_API_URL" ]] || fail_error "SCANNER_API_URL is not set in $CONFIG_FILE"

# --- argument validation -----------------------------------------------------
if [[ $# -lt 1 || $# -gt 3 ]]; then
    fail_error "Usage: $SCRIPT_NAME <file_path> [username] [source_label]"
fi

FILE_PATH="$1"
USERNAME="${2:-${DEFAULT_USERNAME:-$(id -un)}}"
SOURCE_LABEL="${3:-$SOURCE_APPLICATION}"

[[ -e "$FILE_PATH" ]] || fail_error "File does not exist: $FILE_PATH"
[[ -f "$FILE_PATH" ]] || fail_error "Not a regular file: $FILE_PATH"
[[ -r "$FILE_PATH" ]] || fail_error "File not readable: $FILE_PATH"

command -v curl >/dev/null 2>&1 || fail_error "curl is required but not installed"
command -v jq   >/dev/null 2>&1 || fail_error "jq is required but not installed"

log "INFO" "Uploading file=$FILE_PATH user=$USERNAME source=$SOURCE_LABEL"

# --- upload + synchronous wait in one call -----------------------------------
# NOTE: the API key is passed only via the -H header argument to curl,
# never echoed, never placed on the command line as a visible arg, and
# never written to $LOG_FILE.
HTTP_BODY_FILE="$(mktemp)"
trap 'rm -f "$HTTP_BODY_FILE"' EXIT

HTTP_CODE="$(curl -sS -o "$HTTP_BODY_FILE" -w '%{http_code}' \
    --connect-timeout "$SCANNER_CONNECT_TIMEOUT" \
    --max-time "$SCANNER_CURL_TIMEOUT" \
    -X POST "${SCANNER_API_URL%/}/api/v1/files/upload?wait=true&timeout=${SYNC_WAIT_TIMEOUT}" \
    -H "Authorization: Bearer ${API_KEY}" \
    -F "file=@${FILE_PATH}" \
    -F "username=${USERNAME}" \
    -F "source=${SOURCE_LABEL}" \
    ${SCANNER_PROFILE:+-F "profile=${SCANNER_PROFILE}"})"
CURL_EXIT=$?

if [[ $CURL_EXIT -ne 0 ]]; then
    fail_error "curl request failed with exit code $CURL_EXIT (network/timeout unreachable)"
fi

RESPONSE_BODY="$(cat "$HTTP_BODY_FILE")"
log "INFO" "POST /api/v1/files/upload responded http_code=$HTTP_CODE"

if [[ "$HTTP_CODE" != "200" && "$HTTP_CODE" != "202" ]]; then
    MESSAGE="$(echo "$RESPONSE_BODY" | jq -r '.message // "unknown error"' 2>/dev/null)"
    fail_error "Upload rejected http_code=$HTTP_CODE message=$MESSAGE"
fi

SCAN_ID="$(echo "$RESPONSE_BODY" | jq -r '.scan_id // empty' 2>/dev/null)"
[[ -n "$SCAN_ID" ]] || fail_error "API accepted the request but returned no scan_id"

STATUS="$(echo "$RESPONSE_BODY" | jq -r '.status // "ERROR"' 2>/dev/null)"

# --- if the server's own sync-wait timed out before a terminal result,
#     keep polling client-side rather than giving up immediately -------------
case "$STATUS" in
    RECEIVED|VALIDATING|TRANSFERRING|SCANNING|QUEUED)
        log "INFO" "Scan not yet terminal after server-side wait (status=$STATUS) - polling scan_id=$SCAN_ID"
        DEADLINE=$(( $(date +%s) + EXTRA_POLL_TIMEOUT ))
        while true; do
            if (( $(date +%s) >= DEADLINE )); then
                fail_error "Timed out after server wait + ${EXTRA_POLL_TIMEOUT}s extra polling for scan_id=$SCAN_ID"
            fi
            sleep "$EXTRA_POLL_INTERVAL"
            POLL_BODY_FILE="$(mktemp)"
            POLL_HTTP_CODE="$(curl -sS -o "$POLL_BODY_FILE" -w '%{http_code}' \
                --connect-timeout "$SCANNER_CONNECT_TIMEOUT" --max-time "$SCANNER_CURL_TIMEOUT" \
                -X GET "${SCANNER_API_URL%/}/api/v1/scans/${SCAN_ID}" \
                -H "Authorization: Bearer ${API_KEY}")"
            RESPONSE_BODY="$(cat "$POLL_BODY_FILE")"
            rm -f "$POLL_BODY_FILE"
            [[ "$POLL_HTTP_CODE" == "200" ]] || continue
            STATUS="$(echo "$RESPONSE_BODY" | jq -r '.status // "ERROR"' 2>/dev/null)"
            case "$STATUS" in
                RECEIVED|VALIDATING|TRANSFERRING|SCANNING|QUEUED) continue ;;
                *) break ;;
            esac
        done
        ;;
esac

# --- interpret the final, terminal status ------------------------------------
case "$STATUS" in
    CLEAN)
        log "INFO" "Scan CLEAN scan_id=$SCAN_ID file=$FILE_PATH"
        echo "CLEAN: no malware detected"
        exit 0
        ;;
    INFECTED)
        THREATS="$(echo "$RESPONSE_BODY" | jq -r '(.threats // []) | join(", ")' 2>/dev/null)"
        log "WARN" "Scan INFECTED scan_id=$SCAN_ID file=$FILE_PATH threats=$THREATS"
        echo "INFECTED: ${THREATS:-unknown}"
        exit 1
        ;;
    ENCRYPTED)
        ALLOWED="$(echo "$RESPONSE_BODY" | jq -r '.allowed' 2>/dev/null)"
        if [[ "$ALLOWED" == "true" ]]; then
            log "INFO" "Scan ENCRYPTED-but-allowed scan_id=$SCAN_ID file=$FILE_PATH"
            echo "CLEAN: encrypted file allowed by policy (could not be scanned)"
            exit 0
        fi
        log "WARN" "Scan ENCRYPTED-and-denied scan_id=$SCAN_ID file=$FILE_PATH"
        echo "ERROR: encrypted file denied by policy"
        exit 2
        ;;
    *)
        MESSAGE="$(echo "$RESPONSE_BODY" | jq -r '.message // "scan failed"' 2>/dev/null)"
        log "ERROR" "Scan $STATUS scan_id=$SCAN_ID message=$MESSAGE"
        echo "ERROR: $MESSAGE"
        exit 2
        ;;
esac
