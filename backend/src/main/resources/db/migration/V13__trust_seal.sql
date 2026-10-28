-- SOV-040: seal published trust snapshots and bind immutable approval identity.
--
-- Before this migration the runtime role held direct INSERT on every trust
-- table, actor columns were free TEXT, and nothing at the database level
-- stopped late issuer/policy appends to an active version, unapproved or
-- backward activation, or a fabricated approval under a supplied name.
--
-- After it:
-- 1. sovra_app keeps SELECT only on the six trust tables (and loses sequence
--    use): every runtime write goes through the SECURITY DEFINER functions
--    below, which enforce the structural rules no caller can waive.
-- 2. Seal triggers bind EVERYONE including the owner: rows of an activated
--    version are immutable, and activation requires an approved proposal and
--    moves forward only. Genesis (V6) already complies: rows precede the
--    activation row, and the activation carries proposal plus decision.
-- 3. Approval identity is the authenticated account UUID, with optional
--    human binding (OIDC subject + AMR) for BFF-session callers. Genesis
--    rows keep NULL identity, which means "migration seed" and is rejected
--    for new rows. Display names stay as labels only; no rule compares them.
--
-- Residual owner powers (documented, SOV-040 acceptance 4): the migration
-- owner can still INSERT proposal/decision rows directly (subject to the
-- kept V4 self-approval trigger) and DELETE snapshot/activation rows. Those
-- powers are never the application identity (MC-09) and belong to reviewed
-- migrations and break-glass restore, never to runtime code.

ALTER TABLE trust_change_proposal
  ADD COLUMN IF NOT EXISTS proposed_by_account UUID,
  ADD COLUMN IF NOT EXISTS proposed_by_subject TEXT,
  ADD COLUMN IF NOT EXISTS proposed_by_amr TEXT[];
ALTER TABLE trust_proposal_decision
  ADD COLUMN IF NOT EXISTS approved_by_account UUID,
  ADD COLUMN IF NOT EXISTS approved_by_subject TEXT,
  ADD COLUMN IF NOT EXISTS approved_by_amr TEXT[],
  ADD COLUMN IF NOT EXISTS person_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE trust_snapshot
  ADD COLUMN IF NOT EXISTS created_by_account UUID;
ALTER TABLE trust_snapshot_activation
  ADD COLUMN IF NOT EXISTS activated_by_account UUID;

-- Seal: an activated version is immutable for every role. The freshness
-- rule is "activated", not "old": unactivated drafts (fresh proposals)
-- accept no late rows either, because only trust_propose writes them and
-- it writes each version exactly once.
CREATE OR REPLACE FUNCTION reject_sealed_snapshot_write()
RETURNS TRIGGER AS $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM trust_snapshot_activation WHERE snapshot_version = COALESCE(NEW.snapshot_version, OLD.snapshot_version)
  ) THEN
    RAISE EXCEPTION 'snapshot version % is sealed: activated versions are immutable',
      COALESCE(NEW.snapshot_version, OLD.snapshot_version);
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS seal_issuer_record ON issuer_record;
CREATE TRIGGER seal_issuer_record
  BEFORE INSERT OR UPDATE OR DELETE ON issuer_record
  FOR EACH ROW EXECUTE FUNCTION reject_sealed_snapshot_write();
DROP TRIGGER IF EXISTS seal_rp_policy ON rp_policy;
CREATE TRIGGER seal_rp_policy
  BEFORE INSERT OR UPDATE OR DELETE ON rp_policy
  FOR EACH ROW EXECUTE FUNCTION reject_sealed_snapshot_write();

-- Activation is lawful only for an approved version and only forward.
CREATE OR REPLACE FUNCTION require_lawful_activation()
RETURNS TRIGGER AS $$
DECLARE
  approved BIGINT;
  current_max BIGINT;
BEGIN
  SELECT p.snapshot_version INTO approved
  FROM trust_change_proposal p
  JOIN trust_proposal_decision d ON d.proposal_id = p.id
  WHERE p.snapshot_version = NEW.snapshot_version;
  IF approved IS NULL THEN
    RAISE EXCEPTION 'activation refused: version % has no approved proposal', NEW.snapshot_version;
  END IF;
  SELECT COALESCE(MAX(snapshot_version), 0) INTO current_max FROM trust_snapshot_activation;
  IF NEW.snapshot_version <= current_max THEN
    RAISE EXCEPTION 'activation refused: version % does not move forward from %',
      NEW.snapshot_version, current_max;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS lawful_activation_only ON trust_snapshot_activation;
CREATE TRIGGER lawful_activation_only
  BEFORE INSERT ON trust_snapshot_activation
  FOR EACH ROW EXECUTE FUNCTION require_lawful_activation();

-- The V4 self-approval trigger compared display names, which are labels
-- only and not unique. Identity is the account UUID now: replace the
-- trigger with a UUID comparison. NULL identities (migration seed and
-- owner-direct fixture rows) are permitted here; the sealed function
-- requires non-null identity for new runtime rows.
DROP TRIGGER IF EXISTS no_self_approval ON trust_proposal_decision;
CREATE OR REPLACE FUNCTION reject_self_approval()
RETURNS TRIGGER AS $$
DECLARE
  maker UUID;
BEGIN
  SELECT proposed_by_account INTO maker
  FROM trust_change_proposal WHERE id = NEW.proposal_id;
  IF maker IS NOT NULL AND NEW.approved_by_account IS NOT NULL
     AND maker = NEW.approved_by_account THEN
    RAISE EXCEPTION 'self-approval forbidden for proposal %', NEW.proposal_id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER no_self_approval
  BEFORE INSERT ON trust_proposal_decision
  FOR EACH ROW EXECUTE FUNCTION reject_self_approval();

-- The runtime's only write path. Authz (TRUST_ADMIN) stays in Java, which
-- passes the authenticated principal; these functions enforce the
-- structural rules: fresh versions, linked proposals, UUID-distinct
-- maker/checker, and lawful activation.
CREATE OR REPLACE FUNCTION trust_propose(
  maker_account UUID,
  maker_name TEXT,
  maker_subject TEXT,
  maker_amr TEXT[],
  note TEXT,
  issuers JSONB,
  policies JSONB
)
RETURNS TABLE (version BIGINT, proposal_id UUID)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  new_version BIGINT;
  new_proposal UUID := gen_random_uuid();
  issuer JSONB;
  policy JSONB;
BEGIN
  IF maker_account IS NULL OR maker_name IS NULL OR maker_name = '' THEN
    RAISE EXCEPTION 'propose refused: maker identity is required';
  END IF;
  -- Shape rules (required fields, epochs, key versions) stay in the Java
  -- validator; the function only requires present arrays. Empty issuers
  -- are legal: a version may carry RP policies only.
  IF issuers IS NULL OR policies IS NULL THEN
    RAISE EXCEPTION 'propose refused: issuers and policies arrays are required';
  END IF;
  INSERT INTO trust_snapshot (created_by, created_by_account, note)
  VALUES (maker_name, maker_account, COALESCE(note, ''))
  RETURNING trust_snapshot.version INTO new_version;
  FOR issuer IN SELECT * FROM jsonb_array_elements(issuers) LOOP
    INSERT INTO issuer_record (
      snapshot_version, issuer_id, display_name, scope, credential_types,
      key_id, key_version, public_key_jwk, valid_from, valid_through, status
    )
    VALUES (
      new_version,
      issuer->>'issuer_id',
      issuer->>'display_name',
      issuer->>'scope',
      ARRAY(SELECT jsonb_array_elements_text(issuer->'credential_types')),
      issuer->>'key_id',
      (issuer->>'key_version')::INT,
      (issuer->'public_key_jwk')::jsonb,
      (issuer->>'valid_from')::timestamptz,
      (issuer->>'valid_through')::timestamptz,
      issuer->>'status'
    );
  END LOOP;
  FOR policy IN SELECT * FROM jsonb_array_elements(policies) LOOP
    INSERT INTO rp_policy (snapshot_version, rp_id, purpose, allowed_types, max_assurance)
    VALUES (
      new_version,
      policy->>'rp_id',
      policy->>'purpose',
      ARRAY(SELECT jsonb_array_elements_text(policy->'allowed_types')),
      policy->>'max_assurance'
    );
  END LOOP;
  INSERT INTO trust_change_proposal (
    id, snapshot_version, proposed_by, proposed_by_account,
    proposed_by_subject, proposed_by_amr
  )
  VALUES (
    new_proposal, new_version, maker_name, maker_account,
    maker_subject, maker_amr
  );
  version := new_version;
  proposal_id := new_proposal;
  RETURN NEXT;
END;
$$;

CREATE OR REPLACE FUNCTION trust_approve(
  target_proposal UUID,
  checker_account UUID,
  checker_name TEXT,
  checker_subject TEXT,
  checker_amr TEXT[]
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  maker_account UUID;
  maker_subject TEXT;
  verified BOOLEAN;
BEGIN
  IF checker_account IS NULL OR checker_name IS NULL OR checker_name = '' THEN
    RAISE EXCEPTION 'approve refused: checker identity is required';
  END IF;
  SELECT p.proposed_by_account, p.proposed_by_subject
  INTO maker_account, maker_subject
  FROM trust_change_proposal p
  WHERE p.id = target_proposal;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'approve refused: unknown proposal %', target_proposal
      USING ERRCODE = 'no_data_found';
  END IF;
  IF maker_account IS NOT DISTINCT FROM checker_account THEN
    RAISE EXCEPTION 'self-approval forbidden for proposal %', target_proposal;
  END IF;
  IF maker_subject IS NOT NULL AND checker_subject IS NOT NULL
     AND maker_subject = checker_subject THEN
    RAISE EXCEPTION 'approve refused: maker and checker share one person identity';
  END IF;
  IF EXISTS (SELECT 1 FROM trust_proposal_decision WHERE proposal_id = target_proposal) THEN
    RAISE EXCEPTION 'proposal % is already decided', target_proposal
      USING ERRCODE = 'unique_violation';
  END IF;
  verified := maker_subject IS NOT NULL AND checker_subject IS NOT NULL
    AND maker_subject IS DISTINCT FROM checker_subject;
  INSERT INTO trust_proposal_decision (
    proposal_id, approved_by, approved_by_account,
    approved_by_subject, approved_by_amr, person_verified
  )
  VALUES (
    target_proposal, checker_name, checker_account,
    checker_subject, checker_amr, verified
  );
  RETURN verified;
END;
$$;

CREATE OR REPLACE FUNCTION trust_activate(
  target_version BIGINT,
  activator_account UUID,
  activator_name TEXT
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF activator_account IS NULL OR activator_name IS NULL OR activator_name = '' THEN
    RAISE EXCEPTION 'activate refused: activator identity is required';
  END IF;
  INSERT INTO trust_snapshot_activation (snapshot_version, activated_by, activated_by_account)
  VALUES (target_version, activator_name, activator_account);
END;
$$;

-- The runtime role reads trust state but writes only through the functions.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON trust_snapshot FROM sovra_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON trust_snapshot_activation FROM sovra_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON issuer_record FROM sovra_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON rp_policy FROM sovra_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON trust_change_proposal FROM sovra_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON trust_proposal_decision FROM sovra_app;
REVOKE USAGE, SELECT ON SEQUENCE trust_snapshot_version_seq FROM sovra_app;
GRANT EXECUTE ON FUNCTION trust_propose(UUID, TEXT, TEXT, TEXT[], TEXT, JSONB, JSONB) TO sovra_app;
GRANT EXECUTE ON FUNCTION trust_approve(UUID, UUID, TEXT, TEXT, TEXT[]) TO sovra_app;
GRANT EXECUTE ON FUNCTION trust_activate(BIGINT, UUID, TEXT) TO sovra_app;
