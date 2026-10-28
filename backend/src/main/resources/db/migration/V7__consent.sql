-- SOV-010: consent-bound proof requests and minimal holder flow.
--
-- proof_request rows are immutable except for the terminal holder decision
-- (column-level UPDATE on state/decided_at/consent_artifact only): the RP,
-- audience, purpose, exact claims, plan hash, challenge, holder binding and
-- expiry the holder reviews are the values the consent proof must match, so
-- a scope edit after review invalidates the receipt instead of widening it.
-- Consent state is derived at read time (PENDING/DENIED/APPROVED plus
-- expiry and credential-usability checks); no background job rewrites rows.

CREATE TABLE IF NOT EXISTS proof_request (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  credential_id UUID NOT NULL REFERENCES credential_artifact (id),
  rp_id TEXT NOT NULL
    CHECK (char_length(rp_id) BETWEEN 1 AND 256),
  audience TEXT NOT NULL
    CHECK (char_length(audience) BETWEEN 1 AND 256),
  purpose TEXT NOT NULL
    CHECK (char_length(purpose) BETWEEN 1 AND 256),
  claims JSONB NOT NULL,
  plan_hash TEXT NOT NULL
    CHECK (plan_hash ~ '^[0-9a-f]{64}$'),
  challenge TEXT NOT NULL
    CHECK (challenge ~ '^[A-Za-z0-9_-]{16,128}$'),
  holder_thumbprint TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'PENDING'
    CHECK (state IN ('PENDING', 'APPROVED', 'DENIED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  decided_at TIMESTAMPTZ,
  consent_artifact TEXT,
  trust_snapshot_version BIGINT NOT NULL,
  created_by TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS proof_request_tenant_idx ON proof_request (tenant_id);
CREATE INDEX IF NOT EXISTS proof_request_credential_idx ON proof_request (credential_id);

ALTER TABLE proof_request ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON proof_request;
CREATE POLICY tenant_isolation ON proof_request
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());

GRANT SELECT, INSERT ON proof_request TO sovra_app;
GRANT UPDATE (state, decided_at, consent_artifact) ON proof_request TO sovra_app;
