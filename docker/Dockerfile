# =============================================================================
# ClamAV scanner image.
#
# Contains ONLY clamscan + the entrypoint script. Virus definitions are NOT
# baked in or fetched at scan time - they come from the read-only
# `clamav_db` named volume kept fresh by the separate freshclam-updater
# container (Dockerfile.freshclam). This means the scan container never
# needs network access, which is why it always runs with network_mode=none.
# =============================================================================
FROM debian:12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends clamav && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 10001 clamscan && \
    useradd --no-create-home --uid 10001 --gid 10001 --shell /usr/sbin/nologin clamscan && \
    mkdir -p /scan /output && \
    chown -R clamscan:clamscan /scan /output

COPY scan.sh /usr/local/bin/scan.sh
RUN chmod 0755 /usr/local/bin/scan.sh

USER clamscan
WORKDIR /output
ENTRYPOINT ["/usr/local/bin/scan.sh"]
