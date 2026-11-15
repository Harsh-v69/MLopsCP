import os

from alembic import context
from sqlalchemy import create_engine

from src.db.models import Base

url = os.environ.get("MLSHIELD_DB_URL")
if not url:
    raise SystemExit("Set MLSHIELD_DB_URL (e.g. postgresql+psycopg://user:pass@host/db)")

if context.is_offline_mode():
    context.configure(url=url, target_metadata=Base.metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    with create_engine(url).connect() as conn:
        context.configure(connection=conn, target_metadata=Base.metadata)
        with context.begin_transaction():
            context.run_migrations()
