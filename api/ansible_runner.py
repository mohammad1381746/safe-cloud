from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict

from config import settings

logger = logging.getLogger("scanner.ansible")


class AnsibleExecutionError(Exception):
    """Raised whenever a playbook cannot be run to completion or produces
    no usable result. Callers must treat this as a scanner-unavailable
    (fail-closed) condition."""


def run_playbook(
    *,
    run_id: str,
    playbook_path: str,
    limit: str,
    extra_vars: Dict[str, Any],
    timeout: int,
) -> Dict[str, Any]:
    """
    Generic Ansible playbook runner, reused for both scan_pipeline.yml
    (transfer + scan) and delete_infected_source.yml (TOCTOU-checked
    deletion) - the two playbooks this project runs, against different
    `--limit` patterns and with different extra-vars, but identical
    execution/result-handling mechanics.

    Uses a JSON extra-vars FILE (not inline CLI text) so that no
    client-controlled value ever passes through shell interpretation, and
    subprocess.run is called with an argument list (never shell=True) -
    there is no command-injection surface regardless of input content.

    `run_id` scopes the on-disk extra-vars/result files and must be
    unique per invocation (callers use e.g. f"{request_id}-scan" and
    f"{request_id}-delete" so the two playbook runs for one scan never
    collide).
    """
    run_dir = Path(settings.ansible_runs_dir) / run_id
    run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    extra_vars_file = run_dir / "extra_vars.json"
    result_file = run_dir / "result.json"

    full_extra_vars: Dict[str, Any] = dict(extra_vars)
    full_extra_vars["result_file"] = str(result_file)

    extra_vars_file.write_text(json.dumps(full_extra_vars), encoding="utf-8")
    extra_vars_file.chmod(0o600)

    cmd = [
        "ansible-playbook",
        "-i", settings.ansible_inventory_path,
        playbook_path,
        "--limit", limit,
        "-e", f"@{extra_vars_file}",
    ]

    logger.info(json.dumps({
        "event": "ansible_run_start",
        "run_id": run_id,
        "playbook": Path(playbook_path).name,
        "limit": limit,
    }))

    # ansible-playbook only auto-discovers ansible.cfg by looking for
    # ./ansible.cfg relative to its CWD; this process's CWD is the
    # worker's own working directory, not the ansible/ directory, so the
    # path must be passed explicitly via ANSIBLE_CONFIG or ansible.cfg
    # (which redirects Ansible's local scratch/control-path/collections
    # directories away from paths the worker can't write to - see
    # ansible/ansible.cfg) is silently ignored.
    env = os.environ.copy()
    env["ANSIBLE_CONFIG"] = settings.ansible_config_path

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        logger.error(json.dumps({
            "event": "ansible_timeout",
            "run_id": run_id,
            "playbook": Path(playbook_path).name,
            "timeout_s": timeout,
        }))
        raise AnsibleExecutionError("Ansible execution timed out") from exc
    except FileNotFoundError as exc:
        raise AnsibleExecutionError(f"ansible-playbook binary not found: {exc}") from exc

    if proc.returncode != 0:
        # Ansible does not consistently write errors to stderr - many
        # ERROR!-prefixed messages (parser errors, module-resolution
        # failures, etc.) go to stdout instead. Log both tails, or a
        # failure can be effectively silent.
        logger.error(json.dumps({
            "event": "ansible_failed",
            "run_id": run_id,
            "playbook": Path(playbook_path).name,
            "limit": limit,
            "returncode": proc.returncode,
            "stdout_tail": (proc.stdout or "")[-2000:],
            "stderr_tail": (proc.stderr or "")[-2000:],
        }))
        # A non-zero return code does not necessarily mean no result was
        # produced (e.g. a `rescue:` block may have written a precondition
        # failure). Fall through and try to read result_file; only raise
        # here if nothing usable exists.
        if not result_file.exists():
            raise AnsibleExecutionError(f"Ansible playbook failed with exit code {proc.returncode}")

    if not result_file.exists():
        raise AnsibleExecutionError("Ansible playbook did not produce a result file")

    try:
        result = json.loads(result_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise AnsibleExecutionError(f"Failed to parse Ansible result: {exc}") from exc

    if not isinstance(result, dict):
        raise AnsibleExecutionError("Ansible result was not a JSON object")

    return result


def cleanup_run(run_id: str) -> None:
    """Removes the per-run extra-vars/result directory on the control
    node. Always called from a `finally` block by the caller."""
    run_dir = Path(settings.ansible_runs_dir) / run_id
    shutil.rmtree(run_dir, ignore_errors=True)
