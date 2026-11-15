#!/usr/bin/env bash
# Usage: pg_backup_restore.sh backup <container> <out.dump> | restore <container> <in.dump>
# Uses pg_dump/pg_restore inside the Postgres container; restore targets a clean database.
# User and database default to postgres; for the compose stack use PGUSER=mlshield PGDATABASE=mlshield.
PGUSER=${PGUSER:-postgres}; PGDATABASE=${PGDATABASE:-postgres}
set -euo pipefail
cmd=$1; c=$2; f=$3
case $cmd in
  backup)  docker exec "$c" pg_dump -U "$PGUSER" -Fc "$PGDATABASE" > "$f" ;;
  restore) docker exec -i "$c" pg_restore -U "$PGUSER" -d "$PGDATABASE" --clean --if-exists --no-owner < "$f" ;;
  *) echo "backup|restore"; exit 2 ;;
esac
