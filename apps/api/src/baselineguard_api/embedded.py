"""Optional in-process worker loops for local development and single-host demos."""

from __future__ import annotations

import logging
import os
import secrets
import threading
from collections.abc import Callable
from pathlib import Path

from baselineguard_api.config import Settings

logger = logging.getLogger(__name__)


def _ensure_key(path: Path) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(secrets.token_bytes(32))


def start_embedded_workers(settings: Settings) -> Callable[[], None]:
    """Start collector and evaluator loops when BG_EMBEDDED_WORKERS=true; return a stop hook."""
    if not settings.embedded_workers:
        return lambda: None
    from baselineguard_collector.worker import CollectorWorker
    from baselineguard_evaluator.worker import EvaluationWorker

    url = settings.worker_database_url or settings.database_url
    _ensure_key(Path(settings.master_key_file))
    evaluator = EvaluationWorker(
        database_url=url,
        evidence_root=settings.evidence_root,
        master_key_file=settings.master_key_file,
    )
    collector = CollectorWorker(
        database_url=url,
        evidence_root=settings.evidence_root,
        master_key_file=settings.master_key_file,
        known_hosts_file=settings.known_hosts_file,
        allow_loopback_targets=settings.lab_targets and settings.environment != "production",
    )
    stopping = threading.Event()

    def loop(name: str, step: Callable[[], bool]) -> None:
        while not stopping.is_set():
            try:
                worked = step()
            except Exception:  # noqa: BLE001 - keep the loop alive; the job row records failure
                logger.exception("embedded %s worker step failed", name)
                worked = False
            if not worked:
                stopping.wait(1.0)

    def schedule_step() -> bool:
        from baselineguard_persistence.database import get_engine
        from sqlalchemy.orm import Session

        from baselineguard_api.scheduling import run_due_schedules

        with Session(get_engine(url)) as db, db.begin():
            run_due_schedules(db)
        stopping.wait(30.0)
        return True

    threads = [
        threading.Thread(target=loop, args=("scheduler", schedule_step), daemon=True),
        threading.Thread(target=loop, args=("evaluator", evaluator.run_one), daemon=True),
        threading.Thread(target=loop, args=("collector", collector.run_one), daemon=True),
    ]
    for thread in threads:
        thread.start()
    logger.info("embedded collector and evaluator workers started")

    def stop() -> None:
        stopping.set()

    return stop
