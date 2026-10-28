# SOV-004: identity/key providers, revocation and cache contracts

**Version:** 0.3 (task closure with recorded deferrals; independent/deployment review pending).
**Date:** 2026-10-28.
**Task:** [SOV-004](https://github.com/apil-khadka/Sovra/issues/8)
(select identity and key providers with revocation and cache contracts).
**Depends on:** [SOV-001](SOV-001-proof-profile.md),
[SOV-002](SOV-002-locality-custody-boundaries.md).

This record selects the implementation reference for OD-10, OD-13 and OD-18.
It does not close deployment-specific location, provider entitlement, retention or independent-review decisions.
Version 0.2 superseded the deferred provider pick, broad cache allowances and pre-G1 external-review sequencing in version 0.1.
Version 0.3 records SOV-004 task closure: selections made, implemented
subset, and explicit deferrals (§7). No coordinate, algorithm, bound,
or identity changed.
Read the [architecture assessment](../identity-key-provider-architecture.md) for evidence, alternatives, code findings and remaining gates.

## 0. Selected reference and development gate

Human SSO: issuer-local Keycloak, OIDC authorization code plus PKCE through a Spring backend-for-frontend.
Privileged users require hardware-bound phishing-resistant factors with reviewed enrollment/recovery; Sovra independently owns current entitlements, elevation and approval records.
Cloud key/processing reference: Google Cloud KMS with `HSM_SINGLE_TENANT` and Confidential Space attestation-derived workload federation in a mutually supported issuer-approved region.
Issuer signing keys remain non-exportable P-256 HSM keys; signing authorization and claim construction execute in the attested workload, while ECDSA executes in the HSM.
The signing and wrapping roles/keys are separate.
This is a reference profile, not an approved universal cloud location or a working production adapter.
SOV-039 qualifies each issuer's actual location/capability matrix; unsupported locations require a separately reviewed provider profile and never automatic foreign-region fallback.

Synthetic implementation of SOV-006 and G1 work may proceed against these contracts without a production account or completed independent assessment.
SOV-037 records the independent design/privacy assessment before real-data provisioning or processing, and SOV-034 remains the final release gate.
This architecture review does not tick those approval boxes.

Initial-phase budget: no new paid services, subscriptions or hardware purchases.
The cloud HSM/TEE reference is deferred qualification, not an initial provisioning instruction.
Self-hosted identity and existing resources support synthetic development without a paid provider account; actual hosting capacity and any free quota must still be verified.
Confirmed initial launch: a public demo with synthetic identities/documents only, self-hosted Keycloak and no new paid service or hardware purchase.
Real-ID ingestion, production issuers and production credential authority remain disabled.
See the [budget clarification](../identity-key-provider-architecture.md#initial-phase-budget-constraint); real-data gates remain separate and unsatisfied.

## 1. Protocol provider coordinates (OD-10)

Registry: `https://maven.waltid.dev/releases` (verified 2026-10-28; the
`/snapshots` repository is excluded from all builds). `id.walt.*`
coordinates are absent from Maven Central; do not depend on Central
copies appearing.

| Module | Coordinates (v1.2.0) | Role |
| --- | --- | --- |
| VCI issuer | `id.walt.openid4vci:waltid-openid4vci-jvm:1.2.0` | Issuer-side OpenID4VCI 1.0 |
| VP verifier | `id.walt.protocols:waltid-openid4vp-verifier-jvm:1.2.0` | Verifier-side OpenID4VP 1.0 |
| VP models | `id.walt.protocols:waltid-openid4vp-jvm:1.2.0` | Shared VP models (managed; direct use only where the verifier module needs it) |
| SD-JWT | `id.walt.sdjwt:waltid-sdjwt-jvm:1.2.0` | SD-JWT issue/verify format layer |

Rules: pin exact versions plus published checksums (`.sha1` verified
present); review the resolved transitive tree before acceptance; never
depend on `waltid-openid4vc` (legacy draft line, planned deprecation) or
on snapshot versions. Nimbus JOSE+JWT 10.3 (Central, Apache-2.0) remains
the substrate for Sovra-owned JOSE code outside these modules.

Remaining SOV-001 library conditions move to SOV-036: conformance runs
plus the adversarial corpus, Community/Enterprise API review, and Java 25
packaged verification.

## 2. Key algorithms and envelope format (OD-13)

- Signing: ES256 (P-256) only, per SOV-001. No RSA, no Ed25519 at G1.
- Vault envelope (G2 real data): AES-256-GCM, per-object-version DEKs,
  96-bit random nonce per encryption, never reused.
- AAD (authenticated, all fields required): tenant ID, issuer ID,
  object ID/version, purpose, schema version, DEK version. Decryption verifies
  AAD before use; no plaintext is processed before verification.
- KEKs live in KMS/HSM with per-issuer permissions; DEKs are wrapped
  (envelope) and cached only under section 5 bounds.
- G1 synthetic double: a software KEK behind the same interfaces,
  labelled non-production in code, config, and logs. Swapping the double
  for KMS must not change call sites.

## 3. Signing and unwrap interfaces

SOV-009/SOV-012 implement exactly these narrow contracts (names are
binding; packaging follows the backend module map):

- `IssuerSigner.sign(keyRef, payload, aad)`: `keyRef` is
  issuer + key ID + key version. Implementations: `LocalDevSigner` (G1
  only), `KmsSigner` (production). The interface performs per-call
  issuer authorization; possession of a reference never implies
  permission to sign.
- `DataKeyService.generateDataKey(context)` / `unwrapDataKey(keyRef,
  context)`: DEK lifecycle for the vault envelope. Context carries the
  AAD fields from section 2.
- `TrustSnapshotProvider.current()`: returns the versioned trust
  snapshot (issuers, keys, scopes, epochs) under section 5 bounds.
- `StatusEvidenceFetcher.fetch(credentialStatus)`: returns status
  evidence with fetch time and max age; unknown is a first-class
  outcome, never an exception swallowed into success.

## 4. Authentication, MFA, elevation, approvals, identities (OD-10)

- Human authentication: issuer-local Keycloak OIDC with exact issuer/audience/redirect validation and local `(iss, sub)` entitlement mapping.
- Browser sessions: server-held tokens, Secure/HttpOnly cookies, CSRF, fixation protection and explicit reauthentication context checks.
- Privileged enrollment/recovery: reviewed identity evidence plus hardware-bound phishing-resistant authenticators, independently controlled recovery and removal of superseded authority.
- TOTP, email and SMS are not privileged-elevation fallback; general passkey support alone does not prove hardware binding.
- JIT elevation: ticket-bound, maximum 4 hours, least-privilege scope,
  fully logged, auto-revoked; no standing privileged access.
- Independent approvals (2-person rule) for: trust-registry changes,
  key rotation/compromise actions, production config/deploys, and
  approval-policy changes themselves.
- Separate identities, no sharing: workload/app, deploy, migration,
  key-admin, audit-reader. Each has only the permissions its task
  needs; the deploy identity cannot read keys, the app identity cannot
  migrate schemas.

## 5. Revocation, cache, and copy authority (OD-18)

Revocation sources: credential status via Token Status List
(`draft-ietf-oauth-status-list-21`, Standards Track, in RFC Editor
queue — re-pin per release) at issuer status endpoints; issuer-key
trust via versioned SOV-008 snapshots. G1 runs a synthetic status
service implementing the same shapes.

| Cache | Max TTL | Max entries | Invalidation |
| --- | --- | --- | --- |
| Trust snapshot | 60 min (background refresh at 45 min + jitter) | 4 snapshots | Version bump; emergency flag |
| Status evidence | 15 min | 10,000 | Issuer-indicated refresh; emergency flag |
| DEK plaintext | One authorized operation only | 0 cross-request entries | Release references after work; no persisted cache; best-effort buffer clearing without Java-heap zeroization promises |
| Positive permission grant | 60 s for approved non-privileged decisions only | 50,000 | Entitlement/policy epoch plus current deny; privileged operations reauthorize current local state |
| Deny decision | 60 s | 50,000 | Policy-version bump; explicit re-grant |
| Sovra-issued machine tokens | 5 min or token expiry, sooner | 5,000 | Current local grant/epoch checks and emergency stop; external/federated token lifetimes are separately qualified |

Every cached entry carries its policy/snapshot and relevant entitlement version.
A version bump invalidates affected authority, and current deny wins over a cached grant.
The local emergency flag has a maximum five-second freshness bound; stale/unavailable authoritative state fails closed.
Privileged signing, unwrap, approval and elevation reauthorize current local state rather than using a positive decision cache.
Provider IAM propagation, federated-token validity and active-job containment are separately measured and must not be advertised as a five-second cloud revocation guarantee.
Cache sizes are enforced; disabling a key does not recall already released plaintext.

Serving JWKS is revocation-filtered: `/api/issuance/jwks.json`
publishes snapshot-authorized keys inside their validity window minus
any version with a terminal revocation row. Trust snapshots stay
immutable history — the filter applies at serve time only — and
unrevoked rotation keys keep serving for their approved window.
Removal from the JWKS is hygiene, not enforcement: verifiers check
live key status independently on every decision, since previously
cached keys outlive any single JWKS response.

Restored-key inventory: every disaster-recovery restore produces a
signed inventory (key ID, version, location, hash) reconciled against
KMS/HSM before serving resumes; unknown key copies block serving until
explained and approved.

Control-plane failure freezes new approvals and permits only operations whose current local authority/freshness checks still succeed within their declared bounds.
Loss of local authorization/emergency state or database durability fails closed, never through cached permission or a new accepted result.
The five-second local stop target and the provider's separate IAM/key containment delays must be tested independently.
Read replicas require an approved lag bound and cannot supply ambiguous acceptance/replay authority.

## 6. Approval

- [ ] Independent security/privacy review under SOV-037 before real-data provisioning or processing; synthetic contract-driven development may proceed.
- [ ] SOV-039 issuer/location/capability approval and SOV-038 deployed attested key-use/input-path evidence.
- [ ] SOV-001 library conditions 2-4 evidenced in SOV-036.
- [ ] Record revision on any coordinate, algorithm, bound, or identity change.

## 7. SOV-004 task closure (2026-10-28)

The selections this task required are made; implementation of the
synthetic subset is verified. The §6 approvals stay open and gate
real-data and production use.

Selected:

- Human SSO: issuer-local self-hosted Keycloak, OIDC authorization
  code with forced S256 PKCE through the Spring BFF (SOV-006
  synthetic implementation verified against compose Keycloak).
- Key reference: Google Cloud KMS `HSM_SINGLE_TENANT` with
  Confidential Space attestation-derived federation (§0); P-256,
  non-exportable, separate signing/wrapping roles.
- Revocation/cache contracts: §5 bounds, revocation-filtered serving
  JWKS, immutable snapshots, restored-key inventory rule.

Implemented and tested (G1 synthetic):

- BFF login/logout with server-held tokens, Secure/HttpOnly cookies,
  CSRF, AMR-gated privileged roles, and exact-registry startup
  validation; production additionally forbids the demo http
  backchannel escape hatch.
- Revocation-filtered `/api/issuance/jwks.json` with live per-decision
  key-status checks.
- Sealed trust writes (SOV-040): runtime SELECT-only trust tables,
  sealed-function writes, activated-version immutability, UUID
  approval identity, person-verified quorum rule for production.
- Production-entry refusal of synthetic signer, profile, issuers,
  keys, and seed data at startup and on the activation, quorum,
  and verification paths.

Explicitly deferred (not selected, not implemented):

- KMS/HSM provisioning and the production signing adapter
  (G2 provider pick, SOV-038; `KmsSigner` fails loud with 503).
- Live Token Status List endpoints (issuer-operated; G1 status
  service implements the same shapes synthetically).
- Production identity tenant, regions, and entitlements (SOV-039);
  independent assessment (SOV-037); final release (SOV-034).
