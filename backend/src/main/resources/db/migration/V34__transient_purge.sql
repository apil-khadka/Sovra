-- PROD-010: bounded indexed cleanup for expired transient records.
--
-- Maintenance-role separation: the app role holds no DELETE on
-- these tables (LeastPrivilegeTests pins the denial), so each
-- purge is a SECURITY DEFINER function it may only EXECUTE. The
-- function runs as the migration owner, deletes at most p_limit
-- rows per call in expiry order, and returns the removed count.
-- Evidence tables (audit, decisions, credentials, trust history)
-- have no purge path by design.
--
-- Cutoffs: vault grants and idempotency mappings die at expiry
-- (re-issue/recompute is safe past the window); VCI/VP protocol
-- rows keep a 24-hour forensic grace past expiry.

CREATE INDEX IF NOT EXISTS vault_grant_expires_idx ON vault_grant (expires_at);
CREATE INDEX IF NOT EXISTS issuance_idempotency_expires_idx
  ON issuance_idempotency (expires_at);
CREATE INDEX IF NOT EXISTS vci_grant_expires_idx ON vci_grant (expires_at);
CREATE INDEX IF NOT EXISTS vci_token_expires_idx ON vci_token (expires_at);
CREATE INDEX IF NOT EXISTS vp_session_expires_idx ON vp_session (expires_at);

CREATE OR REPLACE FUNCTION purge_expired_vault_grants(p_limit INT)
RETURNS INT LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE removed INT;
BEGIN
  DELETE FROM vault_grant WHERE id IN (
    SELECT id FROM vault_grant WHERE expires_at <= now() ORDER BY expires_at LIMIT p_limit);
  GET DIAGNOSTICS removed = ROW_COUNT;
  RETURN removed;
END $$;
REVOKE ALL ON FUNCTION purge_expired_vault_grants(INT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION purge_expired_vault_grants(INT) TO sovra_app;

CREATE OR REPLACE FUNCTION purge_expired_issuance_idempotency(p_limit INT)
RETURNS INT LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE removed INT;
BEGIN
  DELETE FROM issuance_idempotency WHERE (tenant_id, idempotency_key) IN (
    SELECT tenant_id, idempotency_key FROM issuance_idempotency
    WHERE expires_at <= now() ORDER BY expires_at LIMIT p_limit);
  GET DIAGNOSTICS removed = ROW_COUNT;
  RETURN removed;
END $$;
REVOKE ALL ON FUNCTION purge_expired_issuance_idempotency(INT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION purge_expired_issuance_idempotency(INT) TO sovra_app;

CREATE OR REPLACE FUNCTION purge_expired_vci_grants(p_limit INT)
RETURNS INT LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE removed INT;
BEGIN
  DELETE FROM vci_grant WHERE id IN (
    SELECT id FROM vci_grant WHERE expires_at < now() - interval '24 hours'
    ORDER BY expires_at LIMIT p_limit);
  GET DIAGNOSTICS removed = ROW_COUNT;
  RETURN removed;
END $$;
REVOKE ALL ON FUNCTION purge_expired_vci_grants(INT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION purge_expired_vci_grants(INT) TO sovra_app;

CREATE OR REPLACE FUNCTION purge_expired_vci_tokens(p_limit INT)
RETURNS INT LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE removed INT;
BEGIN
  DELETE FROM vci_token WHERE id IN (
    SELECT id FROM vci_token WHERE expires_at < now() - interval '24 hours'
    ORDER BY expires_at LIMIT p_limit);
  GET DIAGNOSTICS removed = ROW_COUNT;
  RETURN removed;
END $$;
REVOKE ALL ON FUNCTION purge_expired_vci_tokens(INT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION purge_expired_vci_tokens(INT) TO sovra_app;

CREATE OR REPLACE FUNCTION purge_expired_vp_sessions(p_limit INT)
RETURNS INT LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE removed INT;
BEGIN
  DELETE FROM vp_session WHERE id IN (
    SELECT id FROM vp_session WHERE expires_at < now() - interval '24 hours'
    ORDER BY expires_at LIMIT p_limit);
  GET DIAGNOSTICS removed = ROW_COUNT;
  RETURN removed;
END $$;
REVOKE ALL ON FUNCTION purge_expired_vp_sessions(INT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION purge_expired_vp_sessions(INT) TO sovra_app;
