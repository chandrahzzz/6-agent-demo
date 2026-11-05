"""Minimal in-process job runner (no Celery): long agent runs execute on a small thread pool."""
from __future__ import annotations

import logging
import threading
import traceback
from concurrent.futures import Future, ThreadPoolExecutor

log = logging.getLogger("mallya.jobs")
_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="mallya-job")
_jobs: dict[str, Future] = {}
_lock = threading.Lock()


def submit(key: str, fn, *args, **kwargs) -> bool:
    """Run fn in the background. Returns False if a job with this key is already running."""
    with _lock:
        f = _jobs.get(key)
        if f and not f.done():
            return False

        def wrapped():
            try:
                return fn(*args, **kwargs)
            except Exception:
                log.error("job %s failed\n%s", key, traceback.format_exc())
                raise

        _jobs[key] = _pool.submit(wrapped)
        return True


def running(key: str) -> bool:
    f = _jobs.get(key)
    return bool(f and not f.done())
