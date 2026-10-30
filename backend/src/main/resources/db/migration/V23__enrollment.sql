-- SOV-019: enrollment review with maker/checker separation and
-- revision-bound approvals.
--
-- enrollment binds one approved extraction revision to one opaque
-- subject reference and one holder key. Approvals are
-- revision-specific: the approval pins the extraction head, and a
-- later correction invalidates eligibility until re-review.
-- enrollment_review is append-only (no UPDATE or DELETE grant):
-- every decision stays attributable and rejections never delete.
CREATE TABLE IF NOT EXISTS enrollment (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  subject_ref UUID NOT NULL DEFAULT gen_random_uuid(),
  vault_object_id UUID NOT NULL REFERENCES vault_object (id),
  extraction_record_id UUID NOT NULL REFERENCES extraction_record (id),
  bound_revision INT NOT NULL CHECK (bound_revision > 0),
  holder_jwk JSONB NOT NULL,
  state TEXT NOT NULL DEFAULT 'PENDING'
    CHECK (state IN ('PENDING', 'IN_REVIEW', 'APPROVED', 'REJECTED')),
  created_by_account UUID NOT NULL REFERENCES service_account (id),
  created_by TEXT NOT NULL,
  decided_by_account UUID REFERENCES service_account (id),
  decided_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  decided_at TIMESTAMPTZ,
  UNIQUE (tenant_id, subject_ref)
);

CREATE TABLE IF NOT EXISTS enrollment_review (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  enrollment_id UUID NOT NULL REFERENCES enrollment (id),
  revision INT NOT NULL CHECK (revision > 0),
  decision TEXT NOT NULL CHECK (decision IN ('APPROVED', 'REJECTED')),
  binding_proof_ok BOOLEAN NOT NULL,
  reviewer_account UUID NOT NULL REFERENCES service_account (id),
  reviewer TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE enrollment ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON enrollment;
CREATE POLICY tenant_isolation ON enrollment TO sovra_app
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());

ALTER TABLE enrollment_review ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON enrollment_review;
CREATE POLICY tenant_isolation ON enrollment_review TO sovra_app
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());

-- Mutable columns are the review lifecycle only: state, the bound
-- revision (re-review), and the decision attribution. Subject,
-- source, holder key, and creation attribution are immutable.
GRANT SELECT, INSERT,
  UPDATE (state, bound_revision, decided_by_account, decided_by, decided_at)
  ON enrollment TO sovra_app;
GRANT SELECT, INSERT ON enrollment_review TO sovra_app;
