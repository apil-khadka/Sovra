-- SOV-007: durable, append-only, privacy-minimized audit events.
-- The app role can INSERT and SELECT only; no UPDATE or DELETE, ever.
-- Tenant isolation is enforced by row-level security; the tenant setting is
-- strict (missing setting fails the statement instead of leaking rows).

CREATE TABLE IF NOT EXISTS audit_event (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  actor_type TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL DEFAULT '',
  decision TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  policy_version BIGINT NOT NULL,
  correlation_id TEXT NOT NULL DEFAULT '',
  detail JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS audit_event_tenant_time_idx
  ON audit_event (tenant_id, occurred_at);

ALTER TABLE audit_event ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON audit_event;
CREATE POLICY tenant_isolation ON audit_event
  USING (tenant_id = current_setting('app.tenant')::uuid)
  WITH CHECK (tenant_id = current_setting('app.tenant')::uuid);

GRANT SELECT, INSERT ON audit_event TO sovra_app;
