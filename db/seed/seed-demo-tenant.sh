#!/bin/sh
# Seeds the synthetic-demo tenant AFTER Flyway migrations (compose/dev
# only). Production creates tenants through reviewed provisioning,
# never through this seed. Runs as a one-shot compose service: the
# INSERT itself is the readiness probe — it succeeds exactly once V2
# has created the tenant table — and it is a no-op when the slug
# exists. Seeding any earlier (db init scripts) would trip Flyway's
# non-empty-schema guard.
set -eu
: "${SOVRA_DB_URL:?SOVRA_DB_URL is required}"
: "${SOVRA_DB_ADMIN_USER:?SOVRA_DB_ADMIN_USER is required}"
: "${SOVRA_DB_ADMIN_PASSWORD:?SOVRA_DB_ADMIN_PASSWORD is required}"
export PGPASSWORD="$SOVRA_DB_ADMIN_PASSWORD"
HOST=$(printf '%s' "$SOVRA_DB_URL" | sed -e 's|jdbc:postgresql://||' -e 's|/.*||' -e 's|:.*||')
DB=$(printf '%s' "$SOVRA_DB_URL" | sed -e 's|.*/||')
for _ in $(seq 1 90); do
  if psql -h "$HOST" -U "$SOVRA_DB_ADMIN_USER" -d "$DB" -v ON_ERROR_STOP=1 <<'EOF'
INSERT INTO tenant (slug, display_name)
  VALUES ('sovra-demo', 'Synthetic demo tenant')
  ON CONFLICT (slug) DO NOTHING;
EOF
  then
    echo "demo tenant seeded"
    exit 0
  fi
  sleep 2
done
echo "demo tenant seed failed: tenant table never appeared" >&2
exit 1
