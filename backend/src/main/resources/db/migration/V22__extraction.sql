-- SOV-018: local extraction records with protected digests and
-- immutable revisions.
--
-- extraction_record binds one vault source version to one engine
-- run: source digest, engine/schema/normalizer/canonicalization
-- versions, and the current approval pointer. extraction_revision
-- is append-only (the app role holds no UPDATE or DELETE grant):
-- corrections and re-encoding insert new revisions; nothing edits
-- history. Digests are integrity references inside authorized
-- reads, never lookup keys — no index or endpoint resolves by
-- digest (DR-15, SR-24).
CREATE TABLE IF NOT EXISTS extraction_record (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  vault_object_id UUID NOT NULL REFERENCES vault_object (id),
  object_version INT NOT NULL CHECK (object_version > 0),
  source_digest BYTEA NOT NULL CHECK (octet_length(source_digest) = 32),
  engine_id TEXT NOT NULL CHECK (char_length(engine_id) BETWEEN 1 AND 64),
  schema_id TEXT NOT NULL CHECK (char_length(schema_id) BETWEEN 1 AND 64),
  normalizer_id TEXT NOT NULL CHECK (char_length(normalizer_id) BETWEEN 1 AND 64),
  canon_id TEXT NOT NULL CHECK (char_length(canon_id) BETWEEN 1 AND 64),
  approved_revision INT CHECK (approved_revision IS NULL OR approved_revision > 0),
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, vault_object_id, object_version, engine_id)
);

CREATE TABLE IF NOT EXISTS extraction_revision (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  record_id UUID NOT NULL REFERENCES extraction_record (id),
  rev_no INT NOT NULL CHECK (rev_no > 0),
  observed JSONB NOT NULL,
  normalized JSONB NOT NULL,
  confidence NUMERIC(4, 3) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  canonical_digests JSONB NOT NULL,
  exact_digests JSONB NOT NULL,
  supersedes INT CHECK (supersedes IS NULL OR supersedes > 0),
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (record_id, rev_no)
);

ALTER TABLE extraction_record ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON extraction_record;
CREATE POLICY tenant_isolation ON extraction_record TO sovra_app
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());

ALTER TABLE extraction_revision ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON extraction_revision;
CREATE POLICY tenant_isolation ON extraction_revision TO sovra_app
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());

-- The approval pointer is the only mutable extraction column;
-- revisions are insert-only, so history cannot be rewritten.
-- Per-field digests are hex maps keyed by field name; digests
-- are integrity references inside authorized reads, never lookup
-- keys — no index or endpoint resolves by digest (DR-15, SR-24).
GRANT SELECT, INSERT, UPDATE (approved_revision) ON extraction_record TO sovra_app;
GRANT SELECT, INSERT ON extraction_revision TO sovra_app;
