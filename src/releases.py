"""Model releases: register a model artifact once, under an id derived from its content.

A release row holds the object-store key and the SHA-256 of the artifact, so any
API instance (or a restored environment) can fetch the same bytes and prove they
are the bytes that were registered. Usage: python -m src.releases register
"""
import sys
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.db.models import Model, ModelVersion, Project
from src.storage.objects import ObjectStore, sha256_bytes

REPO_ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = REPO_ROOT / "models" / "baseline_model.joblib"
PROJECT_NAME = "mlshield"
MODEL_NAME = "baseline-rf"


def register_release(session: Session, store: ObjectStore, model_path: Path = MODEL_PATH,
                     mlflow_run_id: str | None = None) -> ModelVersion:
    """Idempotent: the same bytes always map to the same release."""
    data = Path(model_path).read_bytes()
    digest = sha256_bytes(data)
    release_id = f"r-{digest[:16]}"

    existing = session.scalar(select(ModelVersion).where(ModelVersion.release_id == release_id))
    if existing:
        return existing

    key = f"releases/{release_id}/{Path(model_path).name}"
    store.put_immutable(key, data)
    sig = Path(str(model_path) + ".sig")
    if sig.exists():
        store.put_immutable(f"releases/{release_id}/{sig.name}", sig.read_bytes())

    project = session.scalar(select(Project).where(Project.name == PROJECT_NAME))
    if project is None:
        project = Project(name=PROJECT_NAME)
        session.add(project)
        session.flush()
    model = session.scalar(select(Model).where(Model.project_id == project.id, Model.name == MODEL_NAME))
    if model is None:
        model = Model(project_id=project.id, name=MODEL_NAME)
        session.add(model)
        session.flush()

    version = ModelVersion(model_id=model.id, release_id=release_id, artifact_key=key,
                           sha256=digest, mlflow_run_id=mlflow_run_id)
    session.add(version)
    session.flush()
    return version


def current_release(session: Session) -> ModelVersion | None:
    return session.scalar(select(ModelVersion).order_by(ModelVersion.id.desc()).limit(1))


def verify_release(version: ModelVersion, store: ObjectStore) -> bool:
    """True only if the stored bytes still hash to what was registered."""
    return sha256_bytes(store.get(version.artifact_key)) == version.sha256


if __name__ == "__main__":
    if sys.argv[1:] != ["register"]:
        raise SystemExit("usage: python -m src.releases register")
    from src.db.session import session_scope
    from src.storage.objects import store_from_env

    store = store_from_env()
    store.ensure_bucket()
    with session_scope() as s:
        v = register_release(s, store)
        print(f"release {v.release_id} sha256={v.sha256}")
