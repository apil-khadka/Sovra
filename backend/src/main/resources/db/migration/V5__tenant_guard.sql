-- Deterministic fail-closed tenant guard for row-level security.
--
-- A pooled connection that previously carried a tenant keeps the app.tenant
-- setting defined-but-empty after RESET, while a fresh connection lacks it
-- entirely. Both states must refuse loudly with one explicit error instead
-- of leaking rows or depending on incidental cast-error wording.

CREATE OR REPLACE FUNCTION app_tenant() RETURNS uuid
  LANGUAGE plpgsql STABLE AS $$
DECLARE
  raw TEXT := NULLIF(current_setting('app.tenant', TRUE), '');
BEGIN
  IF raw IS NULL THEN
    RAISE EXCEPTION 'app.tenant is not set' USING ERRCODE = 'restrict_violation';
  END IF;
  BEGIN
    RETURN raw::uuid;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'app.tenant is not a valid tenant UUID'
      USING ERRCODE = 'restrict_violation';
  END;
END $$;

REVOKE ALL ON FUNCTION app_tenant() FROM PUBLIC, sovra_app;
GRANT EXECUTE ON FUNCTION app_tenant() TO sovra_app;

DROP POLICY IF EXISTS tenant_isolation ON audit_event;
CREATE POLICY tenant_isolation ON audit_event
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());
