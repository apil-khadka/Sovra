-- VP idempotent replay reads the stored decision through the
-- session row; the resolver must expose it. RETURNS TABLE shape
-- changes need drop plus create.
DROP FUNCTION IF EXISTS resolve_vp_session(UUID);
CREATE FUNCTION resolve_vp_session(p_session_id UUID)
RETURNS TABLE (
  id UUID, tenant_id UUID, proof_request_id UUID, nonce TEXT, state TEXT,
  expires_at TIMESTAMPTZ, created_account UUID, decision_id UUID)
LANGUAGE sql STABLE
SECURITY DEFINER
SET search_path = public
AS 'SELECT s.id, s.tenant_id, s.proof_request_id, s.nonce, s.state,
           s.expires_at, s.created_account, s.decision_id
    FROM vp_session s WHERE s.id = p_session_id';

REVOKE ALL ON FUNCTION resolve_vp_session(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION resolve_vp_session(UUID) TO sovra_app;
