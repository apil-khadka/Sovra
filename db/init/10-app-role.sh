#!/bin/sh
# Creates the least-privilege application role with login at first init.
# Migrations (V2) additionally create it NOLOGIN when absent, so the role
# exists in every environment; only this script and tests grant login.
set -eu
: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${SOVRA_APP_DB_PASSWORD:?SOVRA_APP_DB_PASSWORD is required}"
# Escape for a SQL string literal; avoids psql variable interpolation.
ESCAPED_PW=$(printf '%s' "$SOVRA_APP_DB_PASSWORD" | sed "s/'/''/g")
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<EOF
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sovra_app') THEN
    CREATE ROLE sovra_app WITH NOLOGIN;
  END IF;
END
\$\$;
ALTER ROLE sovra_app WITH LOGIN PASSWORD '$ESCAPED_PW';
EOF
