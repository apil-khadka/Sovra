-- SOV-011: durable multi-instance verification and replay-safe acceptance.
--
-- verification_decision rows are INSERT-only for the app role (no
-- UPDATE/DELETE): every verification attempt — ACCEPTED, REJECTED, or
-- UNKNOWN — commits one immutable row, so neither a retry, a second
-- instance, nor a manual follow-up can rewrite stored evidence (FR-31,
-- INV-03). The UNIQUE (tenant_id, request_id, nonce) constraint is the
-- atomic nonce consumption: across any number of instances the first
-- INSERT wins and every loser reconciles against the stored row
-- (INV-01, INV-08, FR-21). The decision row and its audit row commit in
-- one transaction (INV-02). A fresh nonce permits a new attempt; the
-- same nonce replays the stored response byte-for-byte.

CREATE TABLE IF NOT EXISTS verification_decision (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  request_id UUID NOT NULL REFERENCES proof_request (id),
  credential_id UUID NOT NULL REFERENCES credential_artifact (id),
  nonce TEXT NOT NULL
    CHECK (nonce ~ '^[A-Za-z0-9_-]{16,128}$'),
  request_hash TEXT NOT NULL,
  rp_id TEXT NOT NULL,
  audience TEXT NOT NULL,
  outcome TEXT NOT NULL
    CHECK (outcome IN ('ACCEPTED', 'REJECTED', 'UNKNOWN')),
  reason_code TEXT NOT NULL,
  response_body TEXT NOT NULL,
  trust_snapshot_version BIGINT NOT NULL,
  decided_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  decided_by TEXT NOT NULL,
  UNIQUE (tenant_id, request_id, nonce)
);
CREATE INDEX IF NOT EXISTS verification_decision_request_idx
  ON verification_decision (tenant_id, request_id);

ALTER TABLE verification_decision ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON verification_decision;
CREATE POLICY tenant_isolation ON verification_decision
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());

GRANT SELECT, INSERT ON verification_decision TO sovra_app;
