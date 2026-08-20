# =============================================================================
# Shared image for BOTH the `api` and `worker` services (see
# docker-compose.yml: identical `build:`, different `command:`). Runs as
# a non-root user. Only `worker` gets the Docker socket and SSH key
# bind-mounted at runtime - this image itself doesn't assume either.
#
# Build context is the REPO ROOT, not api/ (see docker-compose.yml:
# `context: .`, `dockerfile: api/Dockerfile`), because this image also
# bakes in ansible/scan_pipeline.yml, ansible/delete_infected_source.yml,
# ansible.cfg, and group_vars/ - the playbooks and their config are
# "code": they should ship inside the image, not depend on a runtime bind
# mount that may or may not be populated correctly on every host/OS (this
# is exactly what broke once already - see CLAUDE.md's incident log:
# `ansible-playbook` reported the playbook "could not be found" because a
# bind-mounted ./ansible directory wasn't showing up inside the
# container). ansible/inventory.ini is copied in too as a working
# default, but stays independently overridable at runtime via a
# single-file bind mount on `worker` - see docker-compose.yml - since
# operators legitimately need to add/remove Nextcloud hosts without
# rebuilding.
# =============================================================================
FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-client ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 10002 scanner && \
    useradd --no-create-home --uid 10002 --gid 10002 --shell /usr/sbin/nologin scanner

WORKDIR /app

COPY api/requirements.txt /app/requirements.txt
# ansible-galaxy runs here as root (USER scanner hasn't taken effect yet),
# so its default install path (~/.ansible/collections == /root/.ansible/collections)
# is invisible to the non-root `scanner` user this container actually runs
# as at runtime - ansible-playbook would fail with "couldn't resolve
# module/action 'community.docker.docker_container'". Installing to
# /usr/share/ansible/collections instead (Ansible's system-wide default
# collections path - searched regardless of $HOME) plus making it
# world-readable fixes this for any runtime user.
RUN pip install --no-cache-dir -r /app/requirements.txt && \
    mkdir -p /usr/share/ansible/collections && \
    ansible-galaxy collection install community.docker ansible.posix \
        -p /usr/share/ansible/collections && \
    chmod -R a+rX /usr/share/ansible/collections

COPY api/ /app/
COPY ansible/ /app/ansible/

RUN mkdir -p /var/lib/nextcloud-scanner/runs \
             /var/lib/upload-scanner/staging \
             /var/lib/upload-scanner/quarantine \
             /home/scanner/.ssh && \
    chown -R scanner:scanner /var/lib/nextcloud-scanner /var/lib/upload-scanner /home/scanner /app && \
    chmod 700 /home/scanner/.ssh /var/lib/upload-scanner/quarantine

USER scanner
ENV HOME=/home/scanner
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
