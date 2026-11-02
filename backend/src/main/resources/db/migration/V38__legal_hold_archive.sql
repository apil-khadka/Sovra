-- PROD-010: legal hold and audit archival.
--
-- tenant.legal_hold suspends destruction for that tenant: vault
-- delete/purge refuse, and the archival job skips the tenant's
-- audit rows. Protocol-state purges continue (they carry no
-- content). The flag is set only through the reviewed hold
-- endpoint (TRUST_ADMIN, audited); the grant below is the narrow
-- column the endpoint needs.
ALTER TABLE tenant
  ADD COLUMN IF NOT EXISTS legal_hold BOOLEAN NOT NULL DEFAULT FALSE;

GRANT UPDATE (legal_hold) ON tenant TO sovra_app;

-- audit_event_archive holds evidence past the 90-day hot window:
-- same shape as the live table plus the archival timestamp.
-- Reads union both tables, so archival never hides evidence.
CREATE TABLE IF NOT EXISTS audit_event_archive (LIKE audit_event INCLUDING ALL);

ALTER TABLE audit_event_archive
  ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ NOT NULL DEFAULT now();

ALTER TABLE audit_event_archive ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON audit_event_archive;
-- Same shape as V19: the app_tenant() conjunct leads so a missing
-- setting refuses the whole statement.
CREATE POLICY tenant_isolation ON audit_event_archive TO sovra_app
  USING (app_tenant() IS NOT NULL AND (tenant_id IS NULL OR tenant_id = app_tenant()));

GRANT SELECT ON audit_event_archive TO sovra_app;

-- Bounded nightly archival: rows older than 90 days move to the
-- archive, except held tenants' rows, which stay hot until the
-- hold releases. Platform rows (NULL tenant) archive by age; no
-- hold can cover them because no tenant owns them. SECURITY
-- DEFINER: the app role holds no DELETE on audit_event and only
-- EXECUTE here.
CREATE OR REPLACE FUNCTION archive_audit_events(p_batch INT)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  moved INTEGER;
BEGIN
  WITH doomed AS (
    SELECT e.id
    FROM audit_event e
    LEFT JOIN tenant t ON t.id = e.tenant_id
    WHERE e.occurred_at < now() - interval '90 days'
      AND (e.tenant_id IS NULL OR COALESCE(t.legal_hold, FALSE) = FALSE)
    ORDER BY e.occurred_at
    LIMIT p_batch
    FOR UPDATE OF e SKIP LOCKED
  ),
  carried AS (
    INSERT INTO audit_event_archive
      (id, occurred_at, tenant_id, actor_type, actor_id, action, resource_type,
       resource_id, decision, reason_code, policy_version, correlation_id, detail)
    SELECT id, occurred_at, tenant_id, actor_type, actor_id, action, resource_type,
      resource_id, decision, reason_code, policy_version, correlation_id, detail
    FROM audit_event
    WHERE id IN (SELECT id FROM doomed)
    RETURNING id
  ),
  gone AS (
    DELETE FROM audit_event WHERE id IN (SELECT id FROM carried) RETURNING id
  )
  SELECT count(*) INTO moved FROM gone;
  RETURN moved;
END;
$$;

REVOKE ALL ON FUNCTION archive_audit_events(INT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION archive_audit_events(INT) TO sovra_app;

-- Legal hold reaches the purge function itself: held tenants'
-- bytes never zero, even through direct EXECUTE. The service
-- refuses first with a typed error; this is the backstop.
CREATE OR REPLACE FUNCTION purge_vault_version(p_object_id UUID, p_version INT)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  affected INTEGER;
BEGIN
  IF EXISTS (
    SELECT 1 FROM vault_object_version v
    JOIN tenant t ON t.id = v.tenant_id
    WHERE v.object_id = p_object_id AND v.version = p_version AND t.legal_hold
  ) THEN
    RETURN 0;
  END IF;
  UPDATE vault_object_version
  SET wrapped_dek = ''::bytea,
      dek_nonce = ''::bytea,
      content_nonce = ''::bytea,
      ciphertext = ''::bytea,
      status = 'PURGED',
      status_updated_at = now()
  WHERE object_id = p_object_id AND version = p_version AND status = 'DELETED';
  GET DIAGNOSTICS affected = ROW_COUNT;
  RETURN affected;
END;
$$;

REVOKE ALL ON FUNCTION purge_vault_version(UUID, INT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION purge_vault_version(UUID, INT) TO sovra_app;
