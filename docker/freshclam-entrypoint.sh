#!/bin/sh
#
# Keeps /var/lib/clamav (the shared `clamav_db` named volume) populated
# with current virus definitions. Runs an initial update immediately, then
# repeats on a fixed interval. This is the ONLY container in the stack that
# needs outbound network access - the ephemeral scan container never does.
set -u

INTERVAL_SECONDS="${FRESHCLAM_INTERVAL_SECONDS:-14400}"

echo "[freshclam-updater] running initial database update"
freshclam --stdout || echo "[freshclam-updater] initial update failed, will retry on schedule"

while true; do
    sleep "$INTERVAL_SECONDS"
    echo "[freshclam-updater] running scheduled database update"
    freshclam --stdout || echo "[freshclam-updater] scheduled update failed"
done
