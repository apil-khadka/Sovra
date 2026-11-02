#!/bin/sh
# Fences writers before a restore or failover (PROD-013): revoke
# CONNECT from serving roles, terminate their backends, and verify
# silence. Run against the FENCED cluster (the stale primary), never
# the fresh restore, with the owner credential. Refuses to run
# without --yes to prevent copy-paste fencing of the wrong host.
set -eu
if [ "${1:-}" != "--yes" ]; then
  echo "usage: SOVRA_DB_URL=... SOVRA_DB_ADMIN_PASSWORD=... $0 --yes" >&2
  exit 2
fi
: "${SOVRA_DB_URL:?SOVRA_DB_URL is required}"
: "${SOVRA_DB_ADMIN_PASSWORD:?SOVRA_DB_ADMIN_PASSWORD is required}"
export PGPASSWORD="$SOVRA_DB_ADMIN_PASSWORD"
psql "$SOVRA_DB_URL" -v ON_ERROR_STOP=1 <<'EOF'
REVOKE CONNECT ON DATABASE sovra FROM sovra_app, sovra_quarantine, sovra_backup;
SELECT pg_terminate_backend(pid) FROM pg_stat_activity
  WHERE datname = 'sovra' AND usename IN ('sovra_app', 'sovra_quarantine', 'sovra_backup')
    AND pid <> pg_backend_pid();
EOF
REMAINING=$(psql "$SOVRA_DB_URL" -t -c \
  "SELECT COUNT(*) FROM pg_stat_activity WHERE datname = 'sovra'
   AND usename IN ('sovra_app', 'sovra_quarantine', 'sovra_backup')")
echo "remaining serving backends: $REMAINING"
test "$REMAINING" -eq 0
