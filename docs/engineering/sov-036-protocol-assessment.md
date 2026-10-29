# SOV-036 protocol-layer assessment (G1 synthetic)

Date: 2026-10-29. Verdict: **implemented for the G1 synthetic
scope** with the explicit gaps below. SOV-036 stays open until its
tracker ([issue](https://github.com/apil-khadka/Sovra/issues/40))
is reviewed against this evidence. The decision record is
[SOV-001 v0.5](../architecture/decisions/SOV-001-proof-profile.md#12-sov-036-protocol-layer-qualification-v05-revision);
this document carries the per-criterion evidence.

Scope: OpenID4VCI `pre-authorized_code` / `authorization_code`
(PKCE S256) issuance, OpenID4VP signed request objects with DCQL
plus encrypted `direct_post.jwt` responses, and RFC 9901
KeyBinding JWT holder binding — all over the existing
consent/trust/status/replay/audit gates. The synthetic profile
keeps the Sovra proof message; the `sdjwt-vc` profile binds with
`kb+jwt`.

## Criterion 1 — VCI issuance flows

Done (`dev.sovra.openid`, `V16__openid.sql`, `V17__openid_resolvers.sql`):

- Public credential-issuer metadata names the G1 issuer, the
  token/credential/nonce endpoints, and the single
  `sovra-adult-status-1` configuration (`dc+sd-jwt`, ES256,
  `jwt` proofs). Offers carry the same issuer identifier as
  the metadata document, never the deployment base URL.
- Issuer operators publish `pre-authorized_code` offers; the
  holder's tenant agent drives the synthetic authorization
  server binding a PKCE S256 challenge. Wallet token calls
  carry no service account and resolve the tenant from the
  grant; the grant creator's account is re-validated live.
- Codes, tokens, and `c_nonce` values are 256-bit CSPRNG
  values stored as hashes with 5-minute lifetimes and atomic
  single-use consumption; unknown, expired, or consumed
  grants answer `invalid_grant` without distinguishing
  detail. Batch requests and unknown configurations,
  formats, and proof types are rejected, not partially
  honored.
- The credential endpoint consumes the `c_nonce` atomically
  and delegates to `IssuanceService.issueVci`, so trust,
  allowlist, holder-key, idempotency, and audit gates are
  identical to native issuance. `VciFlowTests` (10) proves
  both grants end to end, including a VCI-issued credential
  completing the consent-to-ACCEPTED circle, and
  `VciConformanceTests` (14) proves the adversarial matrix
  (grant confusion, proof forgery/replay, downgrade,
  expiry, token abuse) fails closed and issues nothing.

Open:

- The applicable external OpenID conformance suites are not
  run (networked registered deployments; infeasible in this
  environment). No production-wallet interop is claimed.
- `invalid_token` at the credential endpoint answers HTTP
  400 with the uniform OAuth2 error shape rather than HTTP
  401; recorded G1 simplification.
- Production replaces the synthetic authorization server
  with the Keycloak-backed AS; the code contract is
  unchanged but the replacement is unbuilt.

## Criterion 2 — VP presentation transport and DCQL

Done:

- The consuming RP opens a session bound to one proof
  request; the wallet fetches a signed ES256 request object
  carrying the nonce, state, DCQL query, and
  `response_mode=direct_post.jwt`, verifiable against the
  public verifier JWKS.
- Responses must be `direct_post.jwt` JWEs to the verifier
  key with exactly `ECDH-ES+A256KW` / `A256GCM` (downgraded
  transports are rejected before decryption); plain
  `direct_post` is rejected outside loopback harness runs.
- The service checks transport, session, state, submission
  shape, and DCQL fulfillment (format, `vct` allowlist,
  disclosed claim paths/values), then delegates the
  decision to `VerificationService`, so consent, freshness,
  trust, replay, and audit gates are identical to the
  native path. `VpFlowTests` (10) proves the encrypted
  acceptance circle, byte-identical replay, and transport
  rejections; `VpConformanceTests` (12) proves JWE abuse,
  binding forgery/replay, foreign-issuer, and
  submission-shape attacks fail closed.
- `DcqlTests` (11) pins the G1 single-credential query and
  match semantics; multi-credential shapes are rejected.

Open:

- G1 presents the issued bytes verbatim (the consented
  claim set is the whole claim set), so selective
  redaction beyond full disclosure is unexercised.
- Same external-conformance-suite gap as criterion 1.

## Criterion 3 — holder binding and independent fixtures

Done:

- `KeyBindingVerifier` verifies RFC 9901 section 8
  KeyBinding JWTs through the qualified walt-id
  `KeyBindingJwt` interface against the credential `cnf`
  key, with pinned `alg`/`typ`, the SOV-001 freshness
  window, and a JDK-recomputed `sd_hash`.
  `KeyBindingTests` (6) qualifies Nimbus-minted bindings
  over walt-id-issued credentials.
- All holder artifacts in protocol tests come from
  `NimbusWallet` (Nimbus JOSE + JDK only, never walt-id):
  VCI proofs, KeyBinding JWTs, encrypted responses, and
  foreign-issuer credentials.
- The checked-in third-party issuer JWKS is pinned to the
  minting key by `ThirdPartyFixturesTests` (2); the issuer
  stays outside every trust snapshot, so its artifacts
  prove the trust gates reject (`ISSUER_KEY_INACTIVE` /
  `invalid_request`).
- `WaltIdVerificationParityTests` (10) and
  `WaltProfileIssuanceTests` (4) drive KeyBinding proofs in
  the `sdjwt-vc` profile; neither parser accepts the
  other's artifacts (mutual exclusion retained).

Open:

- No real third-party wallet build has executed these
  flows; independence is implementation-level (separate
  JOSE stack), not vendor-level.

## Criterion 4 — library interfaces and packaged behavior

Done:

- Format and binding verification reuse the qualified
  walt-id SD-JWT interfaces (`SDJwt`, `KeyBindingJwt`);
  transports are Sovra-owned over Nimbus JOSE 10.3 (the
  SOV-001 substrate) with no new dependency. The walt-id
  VCI issuer-side endpoint handlers and VP verifier2
  session machinery stay pinned but unexercised: they
  carry their own session stores and crypto providers
  that would bypass Sovra's authorization, trust, audit,
  idempotency, RLS-tenancy, and constrained-signer gates,
  so adopting them is SOV-037 re-triage input, not a
  drop-in swap (SOV-001 section 12.2).
- `OpenIdKeysTests` (3) covers the verifier-key round
  trip, JWKS shape, and request-object signing.
- Full backend suite: 460/460 green on Java 25.
  `scripts/e2e-verification.py` passes in both profiles
  with profile-matching bindings; the implemented
  contract is 0.7.0.

Open:

- Strong artifact-digest pinning beyond repository
  checksums (from SOV-001 section 11.1).
- Community-edition API coverage for the unexercised
  walt-id VCI/VP session modules is unconfirmed.
- SOV-037 independent review stays the gate before
  real-data provisioning/processing.
