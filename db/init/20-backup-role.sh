#!/bin/sh
# Creates the dedicated backup role (PROD-013). The role can stream
# base backups and WAL (REPLICATION) and connect to read them; it
# holds no table privileges, so a leaked backup credential cannot
# read or modify application data through SQL. Skipped when the
# password is unset (demo); required in production.
set -eu
if [ -z "${SOVRA_BACKUP_DB_PASSWORD:-}" ]; then
  echo "SOVRA_BACKUP_DB_PASSWORD unset: skipping backup role creation"
else
  : "${POSTGRES_USER:?POSTGRES_USER is required}"
  : "${POSTGRES_DB:?POSTGRES_DB is required}"
  ESCAPED_PW=$(printf '%s' "$SOVRA_BACKUP_DB_PASSWORD" | sed "s/'/''/g")
  psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<EOF
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sovra_backup') THEN
    CREATE ROLE sovra_backup WITH NOLOGIN REPLICATION;
  END IF;
END
\$\$;
ALTER ROLE sovra_backup WITH LOGIN PASSWORD '$ESCAPED_PW' REPLICATION;
EOF
fi
