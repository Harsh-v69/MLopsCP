#!/usr/bin/env bash
# Usage: pg_backup_restore.sh backup <container> <out.dump> | restore <container> <in.dump>
# Uses pg_dump/pg_restore inside the Postgres container; restore targets a clean database.
set -euo pipefail
cmd=$1; c=$2; f=$3
case $cmd in
  backup)  docker exec "$c" pg_dump -U postgres -Fc postgres > "$f" ;;
  restore) docker exec -i "$c" pg_restore -U postgres -d postgres --clean --if-exists --no-owner < "$f" ;;
  *) echo "backup|restore"; exit 2 ;;
esac
