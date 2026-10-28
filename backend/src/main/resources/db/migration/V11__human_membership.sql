-- SOV-006: human membership provisioned from the issuer-local OIDC
-- provider. One row per stable (issuer, subject) pair; the BFF upserts
-- it at login and reloads roles from it on every request, so role
-- removal and revocation take effect on the next call. Revocation is
-- terminal by convention (rows are never deleted, keeping the audit
-- trail joinable); the app role has no DELETE grant.
CREATE TABLE IF NOT EXISTS human_membership (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  roles TEXT[] NOT NULL DEFAULT '{}',
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (issuer, subject)
);
CREATE INDEX IF NOT EXISTS human_membership_tenant_idx ON human_membership (tenant_id);

GRANT SELECT, INSERT ON human_membership TO sovra_app;
GRANT UPDATE (roles, revoked, display_name, updated_at) ON human_membership TO sovra_app;
