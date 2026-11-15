# Data retention, encryption and backup decisions (M2, readiness plan section 8)

These are **proposed defaults for the owner to confirm**, not yet agreed.

| Topic | Default | Why |
|---|---|---|
| Database | PostgreSQL 16, schema in `src/db/models.py`, changes only via Alembic migrations in `migrations/` | Versioned, reviewable schema |
| Large files (models, reports, SBOMs) | Object storage (MinIO/S3), keys are `<release_id>/<sha256>`, never overwritten | Immutable evidence |
| Audit events | Kept for the life of the project; never deleted by the application | The hash chain is only useful if complete |
| Assessments and reports | Kept 2 years, then archived | **[OWNER]** confirm against any institutional rule |
| Encryption in transit | TLS at the public proxy; private network between services | Added with the proxy in M8/M9 |
| Encryption at rest | Disk or volume encryption of the host/cloud; object-store server-side encryption | **[OWNER]** depends on chosen host |
| Backups | `scripts/pg_backup_restore.sh` (pg_dump custom format); daily and before each migration | Restore tested, see plan |
| Restore | Into an empty Postgres; verified by comparing rows and table count | Done once on 2026-11-15 |
