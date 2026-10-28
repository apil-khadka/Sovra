-- SOV-005: tenants, service accounts, emergency flag, least-privilege role.
-- Roles vocabulary (frozen): TENANT_MEMBER, ISSUER_OPS, RP_CLIENT,
-- TRUST_ADMIN, AUDIT_READER, PLANNER. Unknown roles are rejected by the app.

CREATE TABLE IF NOT EXISTS tenant (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9-]{1,64}$'),
  display_name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS service_account (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  name TEXT NOT NULL,
  token_prefix TEXT NOT NULL,
  token_hash BYTEA NOT NULL CHECK (octet_length(token_hash) = 32),
  roles TEXT[] NOT NULL DEFAULT '{}',
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS service_account_prefix_idx ON service_account (token_prefix);

CREATE TABLE IF NOT EXISTS emergency_flag (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO emergency_flag (id, enabled) VALUES (1, FALSE)
ON CONFLICT (id) DO NOTHING;

-- Least-privilege application role. Login + password are granted outside
-- migrations: db/init/10-app-role.sh in Compose, pg-init.sql in tests.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sovra_app') THEN
    CREATE ROLE sovra_app WITH NOLOGIN;
  END IF;
END
$$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
DO $$
BEGIN
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO sovra_app', current_database());
END
$$;
GRANT USAGE ON SCHEMA public TO sovra_app;
GRANT SELECT ON tenant TO sovra_app;
GRANT SELECT ON service_account TO sovra_app;
GRANT SELECT ON emergency_flag TO sovra_app;
