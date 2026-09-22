"""Minimal in-process async job queue.

Single machine, single worker is enough for this scale (a laptop running
scans against one target at a time). Jobs are persisted in SQLite via db.py
so the web dashboard and bot can see status even across restarts.
"""
import asyncio
import logging

from orchestrator import db
from orchestrator.pipeline import run_pipeline

log = logging.getLogger("queue")

_queue: asyncio.Queue = asyncio.Queue()
_worker_task: asyncio.Task | None = None
_current_job_id: int | None = None
_current_task: asyncio.Task | None = None


async def _worker():
    global _current_job_id, _current_task
    while True:
        job_id, root_domain, scope_text = await _queue.get()
        job = db.get_job(job_id)
        if job and job["status"] == "cancelled":
            log.info("job %s was cancelled while queued, skipping", job_id)
            _queue.task_done()
            continue

        log.info("worker picked up job %s (%s)", job_id, root_domain)
        _current_job_id = job_id
        _current_task = asyncio.create_task(run_pipeline(job_id, root_domain, scope_text))
        try:
            await _current_task
        except asyncio.CancelledError:
            log.info("job %s cancelled", job_id)
        except Exception:
            log.exception("job %s crashed", job_id)
        finally:
            _current_job_id = None
            _current_task = None
            _queue.task_done()


def ensure_worker_started():
    global _worker_task
    if _worker_task is None or _worker_task.done():
        _worker_task = asyncio.create_task(_worker())


async def submit_job(root_domain: str, scope_text: str = "") -> int:
    ensure_worker_started()
    job_id = db.create_job(root_domain, scope_text)
    await _queue.put((job_id, root_domain, scope_text))
    return job_id


def cancel_job(job_id: int) -> bool:
    """Cancel a job. Works for the currently-running job (kills its
    subprocess tree via CancelledError propagation) or a still-queued one
    (marked cancelled in the DB so the worker skips it when it comes up)."""
    if _current_job_id == job_id and _current_task and not _current_task.done():
        _current_task.cancel()
        return True
    job = db.get_job(job_id)
    if job and job["status"] == "queued":
        db.update_job_status(job_id, "cancelled", "Cancelled by operator while queued.")
        return True
    return False
