-- PROD-015: accredited RP onboarding with bound credentials.
--
-- service_account.allowed_audiences constrains the audiences a
-- bearer credential may request proofs for (NULL = unconstrained
-- legacy/sandbox accounts). Consent creation rejects audiences
-- outside the credential's list; verification already pins the
-- presentation to the stored audience, so the accredited contract
-- holds end to end. allowed_origins records the accredited exact
-- origins as the audited contract: a self-asserted Origin header is
-- unenforceable against a token thief server-side, so origin
-- enforcement lives at the edge (WAF/CORS) from this record, and
-- server-side origin checks would be theater. Accreditation-minted
-- accounts always carry both lists.
ALTER TABLE service_account
  ADD COLUMN IF NOT EXISTS allowed_origins TEXT[];

ALTER TABLE service_account
  ADD COLUMN IF NOT EXISTS allowed_audiences TEXT[];

-- accreditation is the reviewed path to production RP credentials:
-- an operator requests with exact roles/origins/audiences, a trust
-- admin approves (stepped-up for the interactive path) and the
-- approval mints the bound credential. States move forward only:
-- REQUESTED -> APPROVED|REJECTED, APPROVED -> REVOKED.
CREATE TABLE IF NOT EXISTS accreditation (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  org_name TEXT NOT NULL CHECK (char_length(org_name) BETWEEN 1 AND 128),
  roles TEXT[] NOT NULL,
  origins TEXT[] NOT NULL CHECK (cardinality(origins) >= 1),
  audiences TEXT[] NOT NULL CHECK (cardinality(audiences) >= 1),
  state TEXT NOT NULL DEFAULT 'REQUESTED'
    CHECK (state IN ('REQUESTED', 'APPROVED', 'REJECTED', 'REVOKED')),
  requested_by TEXT NOT NULL,
  decided_by TEXT,
  decided_at TIMESTAMPTZ,
  credential_id UUID REFERENCES service_account (id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS accreditation_by_state
  ON accreditation (tenant_id, state);

ALTER TABLE accreditation ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON accreditation;
CREATE POLICY tenant_isolation ON accreditation TO sovra_app
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());

GRANT SELECT, INSERT ON accreditation TO sovra_app;
GRANT UPDATE (state, decided_by, decided_at, credential_id) ON accreditation TO sovra_app;
GRANT UPDATE (allowed_origins, allowed_audiences) ON service_account TO sovra_app;
