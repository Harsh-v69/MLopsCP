"""Database connection for the API, the worker and the migration job.
The URL comes from MLSHIELD_DB_URL (never a default with credentials)."""
import os
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.orm import Session


@lru_cache
def engine():
    url = os.environ.get("MLSHIELD_DB_URL")
    if not url:
        raise RuntimeError("MLSHIELD_DB_URL is not set (e.g. postgresql+psycopg://user:pass@host/db)")
    return create_engine(url, pool_pre_ping=True)


def db_configured() -> bool:
    return bool(os.environ.get("MLSHIELD_DB_URL"))


@contextmanager
def session_scope():
    with Session(engine()) as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
