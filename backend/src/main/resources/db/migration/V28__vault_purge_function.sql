-- SOV-016 purge hardening: the app role must never rewrite
-- sealed bytes (LeastPrivilegeTests.appRoleCannotRewriteVault),
-- so V27's column grant is revoked again and zeroing moves into
-- this narrow SECURITY DEFINER function, which can only write
-- empty bytes plus the PURGED standing, and only over DELETED
-- rows. Tenant scoping stays in the service, which loads the
-- row through RLS before calling here.
REVOKE UPDATE (wrapped_dek, dek_nonce, content_nonce, ciphertext)
  ON vault_object_version FROM sovra_app;

CREATE OR REPLACE FUNCTION purge_vault_version(p_object_id UUID, p_version INT)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  affected INTEGER;
BEGIN
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
