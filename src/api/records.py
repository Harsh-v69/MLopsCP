"""Routes backed by the database: releases and assessment jobs (M2)."""
from fastapi import APIRouter, Depends, HTTPException

from src.api.deps import requires
from src.db.models import Assessment, ModelVersion
from src.db.session import db_configured, session_scope
from src.jobs.celery_app import run_assessment
from src.releases import current_release

router = APIRouter()


def _need_db():
    if not db_configured():
        raise HTTPException(status_code=503, detail="database is not configured")


@router.get("/releases", dependencies=[Depends(requires("view_model_metrics"))])
def list_releases() -> dict:
    _need_db()
    with session_scope() as s:
        rows = s.query(ModelVersion).order_by(ModelVersion.id.desc()).all()
        return {"releases": [
            {"release_id": v.release_id, "sha256": v.sha256, "artifact_key": v.artifact_key,
             "mlflow_run_id": v.mlflow_run_id, "created_at": v.created_at.isoformat()}
            for v in rows
        ]}


@router.post("/assessments", status_code=202, dependencies=[Depends(requires("run_assessment"))])
def create_assessment() -> dict:
    """Queue a Security Gate run against the current release and return its id at once."""
    _need_db()
    with session_scope() as s:
        version = current_release(s)
        if version is None:
            raise HTTPException(status_code=409, detail="no release is registered")
        row = Assessment(version_id=version.id, status="queued")
        s.add(row)
        s.flush()
        assessment_id = row.id
    try:
        run_assessment.delay(assessment_id)
    except Exception:  # broker unreachable: do not leave a job that will never run
        with session_scope() as s:
            s.get(Assessment, assessment_id).status = "failed"
        raise HTTPException(status_code=503, detail="job queue is unavailable")
    return {"assessment_id": assessment_id, "status": "queued"}


@router.get("/assessments/{assessment_id}", dependencies=[Depends(requires("view_security_gate_result"))])
def get_assessment(assessment_id: int) -> dict:
    _need_db()
    with session_scope() as s:
        row = s.get(Assessment, assessment_id)
        if row is None:
            raise HTTPException(status_code=404, detail="no such assessment")
        version = s.get(ModelVersion, row.version_id)
        return {
            "assessment_id": row.id, "status": row.status, "decision": row.decision,
            "result": row.result, "report_key": row.report_key, "release_id": version.release_id,
            "created_at": row.created_at.isoformat(),
            "finished_at": row.finished_at.isoformat() if row.finished_at else None,
        }
