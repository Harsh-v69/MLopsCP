"""Security Gate assessments as background jobs.

The API creates a row (status 'queued') and returns its id at once; the worker runs
the gate, which takes minutes when it has to scan dependencies, and records the result
and an immutable report in object storage.
"""
import json
from dataclasses import asdict
from datetime import datetime, timezone

from src.db.models import Assessment
from src.security.gate import run_gate
from src.storage.objects import ObjectStore


def execute_assessment(session_factory, assessment_id: int, store: ObjectStore | None) -> str:
    """Run one assessment to completion. Returns the final status."""
    with session_factory() as s:
        row = s.get(Assessment, assessment_id)
        if row is None:
            raise LookupError(f"assessment {assessment_id} does not exist")
        row.status = "running"

    try:
        result = asdict(run_gate())
        status, decision, payload = "done", result["decision"], result
    except Exception as exc:  # recorded, not raised: a failed scan is a result, not a crash
        status, decision, payload = "failed", None, {"error": f"{type(exc).__name__}: {exc}"}

    report_key = None
    if store is not None and status == "done":
        report_key = f"reports/assessment-{assessment_id}.json"
        store.put_immutable(report_key, json.dumps(payload, sort_keys=True, default=str).encode())

    with session_factory() as s:
        row = s.get(Assessment, assessment_id)
        row.status, row.decision, row.result = status, decision, payload
        row.report_key = report_key
        row.finished_at = datetime.now(timezone.utc)
    return status
