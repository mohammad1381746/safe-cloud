#!/bin/sh
#
# Container entrypoint. Scans exactly one file found under $SCAN_INPUT_DIR
# (a directory, not a specific filename - see ansible/tasks/run_one_scanner.yml)
# and writes a machine-readable JSON verdict to $SCAN_OUTPUT_DIR/result.json.
# Falls back to /scan and /output if those env vars aren't set, so this
# image still behaves the same for a manual `docker run` test with the
# old-style bind mounts.
#
# ClamAV exit codes (interpreted explicitly, never treated as a crash):
#   0 = no virus found      -> status CLEAN
#   1 = virus found         -> status INFECTED
#   2 = error occurred      -> status ERROR
set -u

INPUT_DIR="${SCAN_INPUT_DIR:-/scan}"
OUTPUT_DIR="${SCAN_OUTPUT_DIR:-/output}"
RESULT_FILE="$OUTPUT_DIR/result.json"

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n' ' '
}

CLAMSCAN_VERSION="$(clamscan --version 2>/dev/null | head -n1 | sed -E 's#/.*##')"

TARGET="$(find "$INPUT_DIR" -maxdepth 1 -type f | head -n1)"
if [ -z "$TARGET" ]; then
    printf '{"status":"ERROR","message":"no input file found in %s","scanner_version":"%s"}' \
        "$INPUT_DIR" "$(json_escape "$CLAMSCAN_VERSION")" > "$RESULT_FILE"
    exit 2
fi

FILENAME="$(basename "$TARGET")"

SCAN_OUTPUT="$(clamscan --no-summary --stdout "$TARGET" 2>&1)"
CLAMSCAN_EXIT=$?

case "$CLAMSCAN_EXIT" in
    0)
        printf '{"status":"CLEAN","file":"%s","scanner_version":"%s"}' \
            "$(json_escape "$FILENAME")" "$(json_escape "$CLAMSCAN_VERSION")" > "$RESULT_FILE"
        ;;
    1)
        THREAT="$(printf '%s' "$SCAN_OUTPUT" | grep FOUND | head -n1 | sed -E 's/^.*: (.*) FOUND$/\1/')"
        printf '{"status":"INFECTED","file":"%s","threat":"%s","scanner_version":"%s"}' \
            "$(json_escape "$FILENAME")" "$(json_escape "$THREAT")" "$(json_escape "$CLAMSCAN_VERSION")" > "$RESULT_FILE"
        ;;
    *)
        printf '{"status":"ERROR","file":"%s","message":"%s","scanner_version":"%s"}' \
            "$(json_escape "$FILENAME")" "$(json_escape "$SCAN_OUTPUT")" "$(json_escape "$CLAMSCAN_VERSION")" > "$RESULT_FILE"
        ;;
esac

exit "$CLAMSCAN_EXIT"
