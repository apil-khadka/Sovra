-- SOV-020: holder key custody and recovery.
--
-- holder_key is the live registry of enrolled holder keys: one
-- ACTIVE row per enrollment (partial unique index), with
-- COMPROMISED history preserved, never deleted. holder_recovery
-- tracks one loss/theft/compromise case per key at a time (partial
-- unique index on REPORTED): report revokes the key's credentials
-- immediately, recovery activates a fresh proven key. Only public
-- key material is stored — a CHECK rejects any JWK carrying
-- private fields.
CREATE TABLE IF NOT EXISTS holder_key (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  enrollment_id UUID NOT NULL REFERENCES enrollment (id),
  thumbprint TEXT NOT NULL CHECK (char_length(thumbprint) BETWEEN 1 AND 128),
  jwk JSONB NOT NULL CHECK (jwk ? 'kty' AND NOT (jwk ? 'd')),
  status TEXT NOT NULL DEFAULT 'ACTIVE'
    CHECK (status IN ('ACTIVE', 'COMPROMISED')),
  supersedes UUID REFERENCES holder_key (id),
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, thumbprint)
);

CREATE UNIQUE INDEX IF NOT EXISTS holder_key_one_active_per_enrollment
  ON holder_key (tenant_id, enrollment_id) WHERE status = 'ACTIVE';

CREATE TABLE IF NOT EXISTS holder_recovery (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  holder_key_id UUID NOT NULL REFERENCES holder_key (id),
  enrollment_id UUID NOT NULL REFERENCES enrollment (id),
  reason TEXT NOT NULL CHECK (reason IN ('loss', 'theft', 'compromise')),
  state TEXT NOT NULL DEFAULT 'REPORTED'
    CHECK (state IN ('REPORTED', 'RECOVERED')),
  new_key_id UUID REFERENCES holder_key (id),
  reported_by TEXT NOT NULL,
  recovered_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  recovered_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS holder_recovery_one_open_per_key
  ON holder_recovery (tenant_id, holder_key_id) WHERE state = 'REPORTED';

ALTER TABLE holder_key ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON holder_key;
CREATE POLICY tenant_isolation ON holder_key TO sovra_app
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());

ALTER TABLE holder_recovery ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON holder_recovery;
CREATE POLICY tenant_isolation ON holder_recovery TO sovra_app
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());

-- Keys flip to COMPROMISED exactly once; recoveries close with
-- their replacement link. Nothing else mutates.
GRANT SELECT, INSERT, UPDATE (status) ON holder_key TO sovra_app;
GRANT SELECT, INSERT, UPDATE (state, new_key_id, recovered_by, recovered_at)
  ON holder_recovery TO sovra_app;
