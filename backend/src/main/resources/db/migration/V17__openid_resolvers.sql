-- SOV-036: wallet-call resolvers for the OpenID protocol tables.
--
-- Wallet calls (VCI token/nonce/credential, VP request/response) arrive
-- without a service account, so the tenant is unknown until the grant,
-- token, or session resolves. These SECURITY DEFINER functions are the
-- only cross-tenant reads: each resolves exactly one row by its
-- unguessable value (code/token hash, session UUID) and returns it to
-- the Java service, which then pins the tenant context and performs
-- every further read and write through RLS. Direct table access stays
-- tenant-pinned; these functions take no tenant input and therefore
-- cannot be steered across tenants.

CREATE OR REPLACE FUNCTION resolve_vci_grant(p_code_hash TEXT)
RETURNS TABLE (
  id UUID, tenant_id UUID, kind TEXT, issuer_id TEXT, vct TEXT,
  pkce_challenge TEXT, created_account UUID,
  expires_at TIMESTAMPTZ, consumed_at TIMESTAMPTZ)
LANGUAGE sql STABLE
SECURITY DEFINER
SET search_path = public
AS 'SELECT g.id, g.tenant_id, g.kind, g.issuer_id, g.vct, g.pkce_challenge,
           g.created_account, g.expires_at, g.consumed_at
    FROM vci_grant g WHERE g.code_hash = p_code_hash';

REVOKE ALL ON FUNCTION resolve_vci_grant(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION resolve_vci_grant(TEXT) TO sovra_app;

CREATE OR REPLACE FUNCTION resolve_vci_token(p_token_hash TEXT)
RETURNS TABLE (
  id UUID, tenant_id UUID, grant_id UUID, c_nonce TEXT,
  c_nonce_expires_at TIMESTAMPTZ, credential_issued BOOLEAN,
  expires_at TIMESTAMPTZ, kind TEXT, issuer_id TEXT, vct TEXT,
  created_account UUID)
LANGUAGE sql STABLE
SECURITY DEFINER
SET search_path = public
AS 'SELECT t.id, t.tenant_id, t.grant_id, t.c_nonce, t.c_nonce_expires_at,
           t.credential_issued, t.expires_at, g.kind, g.issuer_id, g.vct,
           g.created_account
    FROM vci_token t JOIN vci_grant g ON g.id = t.grant_id
    WHERE t.token_hash = p_token_hash';

REVOKE ALL ON FUNCTION resolve_vci_token(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION resolve_vci_token(TEXT) TO sovra_app;

CREATE OR REPLACE FUNCTION resolve_vp_session(p_session_id UUID)
RETURNS TABLE (
  id UUID, tenant_id UUID, proof_request_id UUID, nonce TEXT, state TEXT,
  expires_at TIMESTAMPTZ, created_account UUID)
LANGUAGE sql STABLE
SECURITY DEFINER
SET search_path = public
AS 'SELECT s.id, s.tenant_id, s.proof_request_id, s.nonce, s.state,
           s.expires_at, s.created_account
    FROM vp_session s WHERE s.id = p_session_id';

REVOKE ALL ON FUNCTION resolve_vp_session(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION resolve_vp_session(UUID) TO sovra_app;
