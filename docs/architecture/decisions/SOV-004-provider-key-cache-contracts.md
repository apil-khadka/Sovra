# SOV-004: identity/key providers, revocation and cache contracts

**Version:** 0.1 (proposed G0 decision, pending independent review).
**Date:** 2026-10-28.
**Task:** [SOV-004](https://github.com/apil-khadka/Sovra/issues/8)
(select identity and key providers with revocation and cache contracts).
**Depends on:** [SOV-001](SOV-001-proof-profile.md),
[SOV-002](SOV-002-locality-custody-boundaries.md).

This record freezes OD-10 (authentication/governance), OD-13 (document
cryptography and processing locations) and OD-18 (revocation/cache/copy
authority). It resolves SOV-001 library condition 1 (artifact registry)
and sets the contracts SOV-005, SOV-009 and SOV-012 implement.

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
  object ID, purpose, schema version, DEK version. Decryption verifies
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

- Human authentication: SSO-backed identity provider (concrete IdP
  selected at G2 with the provider pick); TOTP minimum for operators,
  phishing-resistant MFA (WebAuthn/passkeys) for all privileged roles.
- Privileged enrollment/recovery: in-person or video-verified ceremony
  plus hardware-key binding; recovery needs quorum approval (2-of-n
  security role) and revokes the old factors first.
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
| DEK plaintext | 10 min | 1,000, zeroized on evict | Key rotation/compromise; emergency flag |
| Positive permission grant | 60 s | 50,000 | Policy-version bump; deny wins on conflict |
| Deny decision | 60 s | 50,000 | Policy-version bump; explicit re-grant |
| Own service tokens | 5 min or token expiry, sooner | 5,000 | Revocation signal; emergency flag |

Rules: every cached entry carries its policy/snapshot version; a
version bump invalidates the whole class. A live emergency flag
(5-second TTL, checked on the authorization path) bypasses all caches.
Deny always wins over a conflicting cached grant. Cache sizes are
enforced with bounded eviction; unbounded growth is a bug.

Restored-key inventory: every disaster-recovery restore produces a
signed inventory (key ID, version, location, hash) reconciled against
KMS/HSM before serving resumes; unknown key copies block serving until
explained and approved.

Control/data-plane outage rules: control-plane outage (trust admin,
approvals) freezes new approvals while steady state serves from the
bounded caches above; data-plane (database) outage fails closed with
`UNKNOWN`, never with cached success beyond the stated TTLs. Read
replicas may serve reads only under a recorded replica-lag bound at G2.

## 6. Approval

- [ ] Independent security review of this record (required before SOV-005/SOV-009 start).
- [ ] SOV-001 library conditions 2-4 evidenced in SOV-036.
- [ ] Record revision on any coordinate, algorithm, bound, or identity change.
