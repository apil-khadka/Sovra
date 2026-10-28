-- SOV-017: encrypted quarantine admissions and the isolated worker role.
--
-- Quarantine reuses the vault envelope: admitted bytes seal as vault
-- objects carrying quarantine purposes, so "encrypted local
-- quarantine" inherits the SOV-016 AEAD, grants, and RLS. This table
-- carries the admission state machine only; no content endpoint ever
-- serves quarantine bytes (the worker reads them by role).
--
-- The sovra_quarantine role is the worker's containment boundary
-- (SR-30, MC-02): it reads its assigned vault rows and admission
-- rows and advances admission verdicts. The verdict row is the
-- scan's audit trail. It holds no access to credentials, keys,
-- trust, grants, audit, or tenants, and cannot seal, rewrap, or
-- decide anything else.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sovra_quarantine') THEN
    CREATE ROLE sovra_quarantine WITH NOLOGIN;
  END IF;
END
$$;
DO $$
BEGIN
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO sovra_quarantine', current_database());
END
$$;

CREATE TABLE IF NOT EXISTS quarantine_admission (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  vault_object_id UUID NOT NULL REFERENCES vault_object (id),
  claimed_type TEXT NOT NULL DEFAULT '',
  actual_type TEXT NOT NULL,
  size_bytes INT NOT NULL CHECK (size_bytes > 0),
  content_sha256 BYTEA NOT NULL,
  status TEXT NOT NULL DEFAULT 'QUARANTINED'
    CHECK (status IN ('QUARANTINED', 'SCANNING', 'CLEAN', 'REJECTED', 'PROMOTED')),
  verdict TEXT NOT NULL DEFAULT '',
  image_width INT CHECK (image_width IS NULL OR image_width > 0),
  image_height INT CHECK (image_height IS NULL OR image_height > 0),
  scanned_at TIMESTAMPTZ,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE quarantine_admission ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON quarantine_admission;
-- Scoped to the app role: the worker role evaluates only its own
-- verdict policies below, so its statements never execute the
-- app_tenant() guard it cannot (and must not) satisfy.
CREATE POLICY tenant_isolation ON quarantine_admission TO sovra_app
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());

-- The backend admits, reads, and promotes; only the worker
-- advances verdicts.
GRANT SELECT, INSERT, UPDATE (status) ON quarantine_admission TO sovra_app;

-- Worker containment: assigned-row reads and verdict advances.
-- Nothing else in the database is visible or writable; the verdict
-- row (status/verdict/scanned_at) is the scan's audit trail, so the
-- worker holds no audit, credential, key, trust, grant, or tenant
-- access at all.
GRANT SELECT, UPDATE (status, verdict, image_width, image_height, scanned_at)
  ON quarantine_admission TO sovra_quarantine;
GRANT SELECT (object_id, version, tenant_id, issuer_id, authorized_purposes,
  content_sha256, kek_version, wrapped_dek, dek_nonce, content_nonce,
  ciphertext, status)
  ON vault_object_version TO sovra_quarantine;
GRANT SELECT (id, tenant_id, issuer_id) ON vault_object TO sovra_quarantine;

-- Worker queue access spans tenants (one worker serves every
-- tenant's queue), but the status transition is fenced inside the
-- database: a row is writable only while unscanned, and only into a
-- scanned or scanning state. Even a compromised worker process
-- cannot flip a REJECTED row to CLEAN, touch PROMOTED rows, or
-- re-open history. (Permissive policies OR together with the
-- tenant_isolation policy above.)
DROP POLICY IF EXISTS quarantine_worker_read ON quarantine_admission;
CREATE POLICY quarantine_worker_read ON quarantine_admission
  FOR SELECT TO sovra_quarantine USING (true);
DROP POLICY IF EXISTS quarantine_worker_verdict ON quarantine_admission;
CREATE POLICY quarantine_worker_verdict ON quarantine_admission
  FOR UPDATE TO sovra_quarantine
  USING (status IN ('QUARANTINED', 'SCANNING'))
  WITH CHECK (status IN ('SCANNING', 'CLEAN', 'REJECTED'));
DROP POLICY IF EXISTS quarantine_worker_seal ON vault_object_version;
CREATE POLICY quarantine_worker_seal ON vault_object_version
  FOR SELECT TO sovra_quarantine USING (true);
DROP POLICY IF EXISTS quarantine_worker_object ON vault_object;
CREATE POLICY quarantine_worker_object ON vault_object
  FOR SELECT TO sovra_quarantine USING (true);
