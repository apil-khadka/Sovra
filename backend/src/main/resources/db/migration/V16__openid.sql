-- SOV-036: OpenID4VCI / OpenID4VP protocol state (G1 synthetic profile).
--
-- Three narrowly-scoped tables carry the protocol's single-use values:
-- VCI grants (pre-authorized codes and synthetic-AS authorization codes),
-- VCI access tokens with their holder-proof nonces, and VP sessions bound
-- to approved proof requests. Secrets are stored as SHA-256 hashes, never
-- verbatim; consumption is an atomic conditional UPDATE so two instances
-- cannot redeem the same code or nonce (same shape as the verification
-- nonce constraint in V8). Rows are tenant-isolated via RLS; the app role
-- may only flip the consumption columns, never rewrite a grant's terms.

CREATE TABLE IF NOT EXISTS vci_grant (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  kind TEXT NOT NULL
    CHECK (kind IN ('PRE_AUTH', 'AUTH_CODE')),
  issuer_id TEXT NOT NULL,
  vct TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  -- PKCE S256 challenge for AUTH_CODE grants; NULL for PRE_AUTH.
  pkce_challenge TEXT NULL,
  created_by TEXT NOT NULL,
  created_account UUID NOT NULL REFERENCES service_account (id),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, code_hash)
);
CREATE INDEX IF NOT EXISTS vci_grant_tenant_idx ON vci_grant (tenant_id);

ALTER TABLE vci_grant ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON vci_grant;
CREATE POLICY tenant_isolation ON vci_grant
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());

GRANT SELECT, INSERT ON vci_grant TO sovra_app;
GRANT UPDATE (consumed_at) ON vci_grant TO sovra_app;

CREATE TABLE IF NOT EXISTS vci_token (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  grant_id UUID NOT NULL REFERENCES vci_grant (id),
  token_hash TEXT NOT NULL,
  -- Single-use holder-proof nonce for the credential request; rotated
  -- on every use and consumed atomically with issuance.
  c_nonce TEXT NULL,
  c_nonce_expires_at TIMESTAMPTZ NULL,
  credential_issued BOOLEAN NOT NULL DEFAULT FALSE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, token_hash)
);
CREATE INDEX IF NOT EXISTS vci_token_tenant_idx ON vci_token (tenant_id);

ALTER TABLE vci_token ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON vci_token;
CREATE POLICY tenant_isolation ON vci_token
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());

GRANT SELECT, INSERT ON vci_token TO sovra_app;
GRANT UPDATE (c_nonce, c_nonce_expires_at, credential_issued) ON vci_token TO sovra_app;

CREATE TABLE IF NOT EXISTS vp_session (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  proof_request_id UUID NOT NULL REFERENCES proof_request (id),
  nonce TEXT NOT NULL
    CHECK (nonce ~ '^[A-Za-z0-9_-]{16,128}$'),
  state TEXT NOT NULL DEFAULT 'PENDING'
    CHECK (state IN ('PENDING', 'COMPLETED', 'EXPIRED')),
  decision_id UUID NULL REFERENCES verification_decision (id),
  expires_at TIMESTAMPTZ NOT NULL,
  created_by TEXT NOT NULL,
  created_account UUID NOT NULL REFERENCES service_account (id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, nonce)
);
CREATE INDEX IF NOT EXISTS vp_session_tenant_idx ON vp_session (tenant_id);

ALTER TABLE vp_session ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON vp_session;
CREATE POLICY tenant_isolation ON vp_session
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());

GRANT SELECT, INSERT ON vp_session TO sovra_app;
GRANT UPDATE (state, decision_id) ON vp_session TO sovra_app;
