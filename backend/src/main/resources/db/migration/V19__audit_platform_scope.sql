-- SOV-007 scope fix: global-resource actions (trust registry,
-- issuer signing keys) are platform evidence, not tenant evidence.
-- tenant_id NULL marks a platform row: every tenant reader sees it,
-- no tenant owns it. Tenant-scoped actions keep actor attribution;
-- their isolation is unchanged.
--
-- The app_tenant() conjunct leads so a missing setting still refuses
-- the whole statement: a NULL-tolerant disjunct must never precede
-- the guard, or short-circuit would let unattributed connections
-- read (or write) platform rows.
ALTER TABLE audit_event ALTER COLUMN tenant_id DROP NOT NULL;
DROP POLICY IF EXISTS tenant_isolation ON audit_event;
CREATE POLICY tenant_isolation ON audit_event
  USING (app_tenant() IS NOT NULL AND (tenant_id IS NULL OR tenant_id = app_tenant()))
  WITH CHECK (app_tenant() IS NOT NULL AND (tenant_id IS NULL OR tenant_id = app_tenant()));
