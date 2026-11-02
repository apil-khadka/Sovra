-- PROD-015: durable holder devices and recovery-scoped reissuance.
--
-- holder_device binds the enrollment's key to a named device: a
-- theft report names the DEVICE and the service resolves it to its
-- keys, revoking every credential they authorize. Devices never
-- delete — loss/theft/compromise flips status, preserving the
-- custody trail. holder_key.device_id is nullable only for
-- pre-device keys (backfilled below to 'primary'); new keys always
-- bind. credential_artifact.revoked_by_recovery links each
-- report-time revocation to its recovery case so reissuance replaces
-- exactly the credentials the report killed — never earlier,
-- independently revoked ones. credential_artifact.supersedes chains
-- each reissued credential to the revoked id it replaces.
CREATE TABLE IF NOT EXISTS holder_device (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  enrollment_id UUID NOT NULL REFERENCES enrollment (id),
  label TEXT NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
  status TEXT NOT NULL DEFAULT 'ACTIVE'
    CHECK (status IN ('ACTIVE', 'LOST', 'STOLEN', 'COMPROMISED')),
  reported_by TEXT,
  reported_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, enrollment_id, label)
);

ALTER TABLE holder_key
  ADD COLUMN IF NOT EXISTS device_id UUID REFERENCES holder_device (id);

CREATE INDEX IF NOT EXISTS holder_key_by_device
  ON holder_key (tenant_id, device_id) WHERE status = 'ACTIVE';

ALTER TABLE credential_artifact
  ADD COLUMN IF NOT EXISTS revoked_by_recovery UUID REFERENCES holder_recovery (id);

ALTER TABLE credential_artifact
  ADD COLUMN IF NOT EXISTS supersedes UUID REFERENCES credential_artifact (id);

CREATE INDEX IF NOT EXISTS credential_by_recovery
  ON credential_artifact (tenant_id, revoked_by_recovery)
  WHERE revoked_by_recovery IS NOT NULL;

-- Backfill: pre-device keys belong to a 'primary' device per
-- enrollment, keeping the every-key-has-a-device invariant for all
-- keys that predate this migration. Idempotent on retry.
INSERT INTO holder_device (tenant_id, enrollment_id, label)
  SELECT DISTINCT tenant_id, enrollment_id, 'primary'
  FROM holder_key
  WHERE device_id IS NULL
  ON CONFLICT (tenant_id, enrollment_id, label) DO NOTHING;

UPDATE holder_key live
  SET device_id = device.id
  FROM holder_device device
  WHERE live.device_id IS NULL
    AND device.tenant_id = live.tenant_id
    AND device.enrollment_id = live.enrollment_id
    AND device.label = 'primary';

ALTER TABLE holder_device ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON holder_device;
CREATE POLICY tenant_isolation ON holder_device TO sovra_app
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());

GRANT SELECT, INSERT ON holder_device TO sovra_app;
GRANT UPDATE (status, reported_by, reported_at) ON holder_device TO sovra_app;
GRANT UPDATE (revoked_by_recovery, supersedes) ON credential_artifact TO sovra_app;
