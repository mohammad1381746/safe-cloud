from __future__ import annotations

import json
import logging
import time
from concurrent.futures import Future, ThreadPoolExecutor
from typing import List, NoReturn

import db
from config import settings
from logging_config import configure_logging
from scanner import force_fail_stale, process_scan

configure_logging()
logger = logging.getLogger("scanner.worker")


def _process_one(scan: dict) -> None:
    scan_id = str(scan["id"])
    try:
        process_scan(scan)
    except Exception:  # noqa: BLE001 - a job must never crash the worker process
        logger.exception(json.dumps({"event": "worker_unhandled_exception", "scan_id": scan_id}))
        try:
            db.update_scan(
                scan_id,
                status="ERROR",
                allowed=False,
                error_message="Internal worker error",
            )
        except Exception:  # noqa: BLE001
            logger.exception(json.dumps({
                "event": "worker_failed_to_record_error", "scan_id": scan_id,
            }))


def _sweep_stale() -> None:
    """Safety net for STAGING_MAX_LIFETIME_SECONDS - forces any job stuck
    in an in-progress state (e.g. from a crashed worker process) to
    ERROR and reclaims its staging directory."""
    try:
        stale = db.find_stale_processing_scans(settings.staging_max_lifetime_seconds)
    except Exception:  # noqa: BLE001
        logger.exception(json.dumps({"event": "stale_sweep_query_failed"}))
        return

    for scan in stale:
        try:
            force_fail_stale(scan)
        except Exception:  # noqa: BLE001
            logger.exception(json.dumps({
                "event": "stale_sweep_force_fail_error", "scan_id": str(scan.get("id")),
            }))


def main() -> NoReturn:
    logger.info(json.dumps({
        "event": "worker_started",
        "concurrency": settings.worker_concurrency,
        "poll_interval_s": settings.worker_poll_interval_seconds,
    }))

    sweep_interval = max(settings.staging_max_lifetime_seconds / 4, 60)
    last_sweep = 0.0
    in_flight: List[Future] = []

    with ThreadPoolExecutor(max_workers=settings.worker_concurrency) as pool:
        while True:
            in_flight = [f for f in in_flight if not f.done()]
            capacity = settings.worker_concurrency - len(in_flight)

            claimed_any = False
            for _ in range(max(capacity, 0)):
                try:
                    scan = db.claim_next_scan()
                except Exception:  # noqa: BLE001 - transient DB issue, don't crash the loop
                    logger.exception(json.dumps({"event": "claim_query_failed"}))
                    break
                if scan is None:
                    break
                claimed_any = True
                logger.info(json.dumps({
                    "event": "scan_claimed",
                    "scan_id": str(scan["id"]),
                    "request_id": scan["request_id"],
                }))
                in_flight.append(pool.submit(_process_one, scan))

            now = time.monotonic()
            if now - last_sweep > sweep_interval:
                _sweep_stale()
                last_sweep = now

            if not claimed_any:
                time.sleep(settings.worker_poll_interval_seconds)


if __name__ == "__main__":
    main()
