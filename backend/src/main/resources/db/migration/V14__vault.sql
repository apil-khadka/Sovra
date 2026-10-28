-- SOV-016: encrypted local vault and purpose-bound grants.
--
-- Envelope layout per object version: fresh random DEK (AES-256-GCM)
-- for content, DEK wrapped under a versioned tenant KEK
-- (AES-256-GCM with wrap context). No plaintext key is ever
-- persisted: the KEK registry below names versions only. Synthetic
-- KEKs derive from configured seed material (HKDF-SHA256, demo
-- only, production refuses to boot with it); production KEKs come
-- from the G2 KMS pick (SOV-038).
--
-- Object versions are immutable except terminal delete (status
-- columns only); grants are immutable except terminal revocation.
-- Ciphertext lives in BYTEA (16 MB cap, DB-enforced) so versions
-- stay transactional with their grants, audit, and RLS.

CREATE TABLE IF NOT EXISTS vault_kek (
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  version INT NOT NULL CHECK (version > 0),
  algorithm TEXT NOT NULL DEFAULT 'AES-256-GCM-HKDF-SHA256',
  status TEXT NOT NULL DEFAULT 'ACTIVE'
    CHECK (status IN ('ACTIVE', 'RETIRED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, version)
);

CREATE TABLE IF NOT EXISTS vault_object (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  issuer_id TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vault_object_version (
  object_id UUID NOT NULL REFERENCES vault_object (id),
  version INT NOT NULL CHECK (version > 0),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  issuer_id TEXT NOT NULL,
  authorized_purposes TEXT[] NOT NULL
    CHECK (cardinality(authorized_purposes) > 0),
  content_sha256 BYTEA NOT NULL,
  kek_version INT NOT NULL CHECK (kek_version > 0),
  wrapped_dek BYTEA NOT NULL,
  dek_nonce BYTEA NOT NULL,
  content_nonce BYTEA NOT NULL,
  ciphertext BYTEA NOT NULL
    CHECK (octet_length(ciphertext) <= 16777216),
  status TEXT NOT NULL DEFAULT 'VALID'
    CHECK (status IN ('VALID', 'DELETED')),
  status_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (object_id, version)
);

CREATE TABLE IF NOT EXISTS vault_grant (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  object_id UUID NOT NULL,
  object_version INT NOT NULL CHECK (object_version > 0),
  principal_type TEXT NOT NULL
    CHECK (principal_type IN ('service_account', 'human_membership')),
  principal_id UUID NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose ~ '^[a-z0-9-]{1,64}$'),
  workload TEXT NOT NULL CHECK (workload ~ '^[a-z0-9-]{1,64}$'),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (expires_at > created_at),
  FOREIGN KEY (object_id, object_version)
    REFERENCES vault_object_version (object_id, version)
);

ALTER TABLE vault_kek ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_object ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_object_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_grant ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON vault_kek;
CREATE POLICY tenant_isolation ON vault_kek
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());
DROP POLICY IF EXISTS tenant_isolation ON vault_object;
CREATE POLICY tenant_isolation ON vault_object
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());
DROP POLICY IF EXISTS tenant_isolation ON vault_object_version;
CREATE POLICY tenant_isolation ON vault_object_version
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());
DROP POLICY IF EXISTS tenant_isolation ON vault_grant;
CREATE POLICY tenant_isolation ON vault_grant
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());

GRANT SELECT, INSERT ON vault_kek TO sovra_app;
GRANT UPDATE (status) ON vault_kek TO sovra_app;
GRANT SELECT, INSERT ON vault_object TO sovra_app;
GRANT SELECT, INSERT ON vault_object_version TO sovra_app;
GRANT UPDATE (status, status_updated_at) ON vault_object_version TO sovra_app;
GRANT SELECT, INSERT ON vault_grant TO sovra_app;
GRANT UPDATE (revoked) ON vault_grant TO sovra_app;
