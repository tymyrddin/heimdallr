"""A tiny in-process job runner.

Loads and detection runs can take a while (the route-leak bundle is ~36k events),
so they run on a single background worker thread and the page polls their status:
queued -> running -> complete | error. Serial on purpose: one OpenSearch lab, one
thing happening at a time, and the order is visible. Nothing here is persisted; the
durable record of a detection run is the Run document in heimdallr-runs.
"""
from __future__ import annotations

import queue
import threading
import time
import traceback
import uuid

_jobs: dict[str, dict] = {}
_lock = threading.Lock()
_q: "queue.Queue[tuple[str, callable]]" = queue.Queue()


def submit(kind: str, label: str, fn) -> str:
    job_id = uuid.uuid4().hex[:12]
    with _lock:
        _jobs[job_id] = {
            "id": job_id, "kind": kind, "label": label, "status": "queued",
            "submitted": time.time(), "started": None, "finished": None,
            "result": None, "error": None,
        }
    _q.put((job_id, fn))
    return job_id


def get(job_id: str) -> dict | None:
    with _lock:
        j = _jobs.get(job_id)
        return dict(j) if j else None


def recent(limit: int = 20) -> list[dict]:
    with _lock:
        items = sorted(_jobs.values(), key=lambda j: j["submitted"], reverse=True)
        return [dict(j) for j in items[:limit]]


def active() -> list[dict]:
    with _lock:
        return [dict(j) for j in _jobs.values() if j["status"] in ("queued", "running")]


def _set(job_id: str, **fields) -> None:
    with _lock:
        if job_id in _jobs:
            _jobs[job_id].update(fields)


def _worker() -> None:
    while True:
        job_id, fn = _q.get()
        _set(job_id, status="running", started=time.time())
        try:
            result = fn()
            _set(job_id, status="complete", finished=time.time(), result=result)
        except Exception as exc:  # noqa: BLE001 - surface any failure to the page
            _set(job_id, status="error", finished=time.time(),
                 error=f"{exc}\n{traceback.format_exc()}")
        finally:
            _q.task_done()


_thread = threading.Thread(target=_worker, name="heimdallr-jobs", daemon=True)
_thread.start()