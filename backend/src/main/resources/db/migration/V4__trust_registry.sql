-- SOV-008: versioned trust registry and approved RP policies.
-- Federation metadata is global (no tenant RLS). Revisions are immutable:
-- the app role can INSERT and SELECT only; activation is a separate row,
-- and every activation needs a two-person approved proposal recorded here.

CREATE TABLE IF NOT EXISTS trust_snapshot (
  version BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS trust_snapshot_activation (
  snapshot_version BIGINT PRIMARY KEY REFERENCES trust_snapshot (version),
  activated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  activated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS issuer_record (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  snapshot_version BIGINT NOT NULL REFERENCES trust_snapshot (version),
  issuer_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  scope TEXT NOT NULL,
  credential_types TEXT[] NOT NULL,
  key_id TEXT NOT NULL,
  public_key_jwk JSONB NOT NULL,
  valid_from TIMESTAMPTZ NOT NULL,
  valid_through TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
  UNIQUE (snapshot_version, issuer_id, key_id)
);

CREATE TABLE IF NOT EXISTS rp_policy (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  snapshot_version BIGINT NOT NULL REFERENCES trust_snapshot (version),
  rp_id TEXT NOT NULL,
  purpose TEXT NOT NULL,
  allowed_types TEXT[] NOT NULL,
  max_assurance TEXT NOT NULL,
  UNIQUE (snapshot_version, rp_id, purpose)
);

CREATE TABLE IF NOT EXISTS trust_change_proposal (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  snapshot_version BIGINT NOT NULL UNIQUE REFERENCES trust_snapshot (version),
  proposed_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS trust_proposal_decision (
  proposal_id UUID PRIMARY KEY REFERENCES trust_change_proposal (id),
  approved_by TEXT NOT NULL,
  decided_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Two-person rule at the database level: the checker cannot be the maker.
CREATE OR REPLACE FUNCTION reject_self_approval()
RETURNS TRIGGER AS $$
BEGIN
  IF (SELECT proposed_by FROM trust_change_proposal WHERE id = NEW.proposal_id)
     = NEW.approved_by THEN
    RAISE EXCEPTION 'self-approval forbidden for proposal %', NEW.proposal_id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS no_self_approval ON trust_proposal_decision;
CREATE TRIGGER no_self_approval
  BEFORE INSERT ON trust_proposal_decision
  FOR EACH ROW EXECUTE FUNCTION reject_self_approval();

GRANT SELECT, INSERT ON trust_snapshot TO sovra_app;
GRANT SELECT, INSERT ON trust_snapshot_activation TO sovra_app;
GRANT SELECT, INSERT ON issuer_record TO sovra_app;
GRANT SELECT, INSERT ON rp_policy TO sovra_app;
GRANT SELECT, INSERT ON trust_change_proposal TO sovra_app;
GRANT SELECT, INSERT ON trust_proposal_decision TO sovra_app;
GRANT USAGE, SELECT ON SEQUENCE trust_snapshot_version_seq TO sovra_app;
