"""Celery worker entry point: `celery -A src.jobs.celery_app worker`.
Broker URL from MLSHIELD_REDIS_URL. Set MLSHIELD_CELERY_EAGER=1 to run tasks inline (tests, no Redis)."""
import os

from celery import Celery

from src.db.session import session_scope
from src.jobs.assessments import execute_assessment

app = Celery("mlshield", broker=os.environ.get("MLSHIELD_REDIS_URL", "memory://"))
app.conf.task_always_eager = bool(os.environ.get("MLSHIELD_CELERY_EAGER"))
app.conf.task_acks_late = True            # a worker that dies mid-job leaves it to be redelivered
app.conf.worker_prefetch_multiplier = 1   # one long scan per worker slot, not a queue of them


@app.task(name="mlshield.run_assessment")
def run_assessment(assessment_id: int) -> str:
    from src.storage.objects import store_from_env

    try:
        store = store_from_env()
    except RuntimeError:  # storage not configured: still run the gate, just no report file
        store = None
    return execute_assessment(session_scope, assessment_id, store)
