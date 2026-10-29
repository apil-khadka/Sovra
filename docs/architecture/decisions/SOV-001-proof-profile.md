# SOV-001: proof profile decision record

**Version:** 0.5 (protocol-layer qualification recorded against the Sovra corpus; external conformance suites and independent review pending).
**Date:** 2026-10-29 (v0.1 through v0.5; sections 9, 10, 11, and 12 record sequencing revisions).
**Task:** [SOV-001](https://github.com/apil-khadka/Sovra/issues/5)
(freeze proof profile, issuer assurance, freshness and session semantics).
**Owner decision:** full interoperable profile now; the narrow-attestation
first step and the conditional framing of SOV-036 are superseded.
SOV-036 interop evidence is now required before the SOV-034 release decision.

This record freezes OD-01 (proof profile/library), OD-03 (trust/status
policy), OD-06 (session/idempotency policy) and OD-14 (enrollment/source
assurance). Profile-dependent Java work (SOV-005, SOV-008 through SOV-012,
SOV-035) must implement exactly this profile; any deviation needs a new
recorded revision and re-review. Section 9 records the G1 issuance
implementation note under that change process.

## 1. Credential format and specifications (OD-01)

| Layer | Frozen choice | Source |
| --- | --- | --- |
| Credential container | SD-JWT VC per `draft-ietf-oauth-sd-jwt-vc-22` (2026-10-27); re-pin on every release until the draft becomes an RFC | [datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) |
| Selective disclosure | SD-JWT per RFC 9901 (November 2025) | [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html) |
| Issuance protocol | OpenID4VCI 1.0 Final (September 2025) | [spec](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) |
| Presentation protocol | OpenID4VP 1.0 Final (July 2025) with DCQL queries | [spec](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) |
| Holder binding | KeyBinding JWT (`kb+jwt`) per RFC 9901, bound to verifier nonce and audience | RFC 9901, Section 8 |
| Signature algorithm | ES256 only at G1; Ed25519 is a recorded extension path, not an accepted algorithm | This record |
| Holder and issuer keys | P-256; issuer verification keys pinned through the SOV-008 trust registry | SOV-008 |

W3C Verifiable Credentials Data Model, mdoc/mDL, Presentation Exchange, and
`jwt_vc_json-ld` are explicitly out of scope for this profile even where a
dependency supports them. The verifier must reject offered formats outside
this table rather than negotiate down.

Issuance flows in scope: `pre-authorized_code` first, then `authorization_code`
against a synthetic authorization server. Presentation transport:
`direct_post.jwt` (JWE-encrypted responses to the verifier key) with signed
request objects; unencrypted `direct_post` is rejected outside loopback test
harness runs.

## 2. Credential type and scope semantics (OD-01)

Sovra credential types are SD-JWT VC `vct` URIs under a Sovra namespace.
Synthetic G1 values use the reserved `example` host so they can never be
mistaken for production types:

| Claim set | `vct` | Scope binding |
| --- | --- | --- |
| Adult status | `https://sovra.example/vct/adult-status/1` | `adultOver18: true` only |
| Future types | `https://sovra.example/vct/<name>/<version>` | Frozen per type before use |

Production `vct` values require a recorded SOV-008 revision with the real
namespace, issuer accreditation scope, and trust epoch. A valid signature
never implies issuer authority, claim truth, or relying-party KYC sufficiency;
SOV-005 authorization and SOV-008 trust checks decide acceptance.

## 3. Protocol library selection (OD-01)

| Candidate | Role coverage | Release | License | Verdict |
| --- | --- | --- | --- | --- |
| walt-id `waltid-identity` (`waltid-openid4vci`, `waltid-openid4vp`, `waltid-sdjwt`) | Issuer + verifier + wallet | v1.2.0, Apache-2.0, private reporting to security@walt.id (5-day ack / 10-day triage) | Apache-2.0 | **Selected, conditional** (conditions below) |
| EUDI `eudi-lib-jvm-openid4vci-kt` v0.15.0 / `eudi-lib-jvm-siop-openid4vp-kt` v0.16.2 | Wallet role only | Apache-2.0 | Apache-2.0 | Rejected for backend roles; no issuer/verifier implementation |
| EUDI `eudi-lib-jvm-sdjwt-kt` v0.20.2 | Both sides, format level | Apache-2.0 | Apache-2.0 | Reserve candidate for SD-JWT format work if walt-id fails validation |
| Nimbus JOSE+JWT 10.3 | Primitives only (no VCI/VP/SD-JWT) | Apache-2.0 | Apache-2.0 | Substrate for Sovra-owned JOSE code, not a protocol implementation |

Sources: [walt-id releases](https://github.com/walt-id/waltid-identity/releases),
[walt-id security policy](https://github.com/walt-id/waltid-identity/security/policy),
[EUDI VCI](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vci-kt/releases),
[EUDI VP](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-siop-openid4vp-kt/releases),
[EUDI SD-JWT](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-sdjwt-kt/releases),
[Nimbus](https://connect2id.com/products/nimbus-jose-jwt).

The walt-id selection is conditional on all of the following, owned by
SOV-004/SOV-036 before protocol-dependent flows are accepted:

1. Resolve the artifact registry: **done in
   [SOV-004](SOV-004-provider-key-cache-contracts.md)** — releases live at
   `https://maven.waltid.dev/releases` with pinned v1.2.0 coordinates plus
   checksums; `id.walt.*` remains absent from Maven Central.
2. Pass the OpenID conformance suites the project claims plus Sovra's
   adversarial corpus (tampered disclosures, wrong audience/nonce, replayed
   presentations, revoked issuer keys, draft-22 edge cases).
3. Complete license, transitive-dependency, and support review; confirm
   Community-edition APIs cover every selected module (no Enterprise-only
   dependency in the issuance/verification path).
4. Verify behavior on Java 25 with a packaged production configuration.

If any condition fails, stop and re-triage: narrow the profile or select a
new library. Do not fork protocol code into Sovra as a shortcut.

## 4. Trust and status freshness policy (OD-03)

| Parameter | Frozen value |
| --- | --- |
| Clock skew allowance | 5 minutes, applied symmetrically to `exp`/`nbf`/`iat` checks |
| Credential status max age | 15 minutes from status evidence to verification decision |
| Trust-registry snapshot max age | 60 minutes; snapshot version is recorded in every decision |
| Unknown/unreachable status | Fail closed (`REJECTED`) in all assurance levels at G1 |
| Revoked issuer key or credential | Terminal `REVOKED`; replacement needs a new identifier and artifact |
| Key-rotation race | The trust snapshot active at decision time governs; rotation must never silently promote an untrusted issuer to trusted |

Status privacy: per-credential status endpoints are issuer oracles. G1 uses
synthetic status with no correlatable identifiers; production status privacy
(Token Status List or equivalent) is a G2 requirement, not a G1 property.

## 5. Session and idempotency policy (OD-06)

| Parameter | Frozen value |
| --- | --- |
| Presentation challenge | 128-bit CSPRNG nonce, single-use, atomic consume, scoped to relying party + plan hash + expiry |
| Challenge lifetime | 5 minutes; expired challenges are rejected, never refreshed in place |
| Issuance idempotency | Client-provided idempotency key, 24-hour retention; same key returns the original response byte-for-byte |
| Retry after response loss | Retry with the same idempotency key; the server reconciles before answering and reports `UNKNOWN` rather than assuming success |
| Uncertain commit recovery | Fence the writer, reconcile against durable state, then report; uncertainty never becomes acceptance (see the [consistency contract](../consistency-and-failure-modes.md)) |

## 6. Enrollment and source-change assurance (OD-14)

- Evidence validation: issuer checks the source document plus a holder-binding
  ceremony (key proof at enrollment) before any credential is signed.
- Separation: production issuance authority needs maker/checker approval;
  the same identity cannot approve its own evidence.
- Corrections and duplicates: corrections issue a new credential version and
  revoke the old one; merges keep one surviving record with a recorded
  supersession link. Silent mutation is forbidden.
- Source refresh: a changed source re-triggers validation; derived
  credentials are re-issued or revoked, never patched.
- G1 synthetic enrollment is a labelled double implementing this shape with
  fixture data; it satisfies no production assurance claim.

## 7. Fixture corpus

Freeze alongside implementation (SOV-011/SOV-035): one valid SD-JWT VC
presentation per flow, plus invalid cases for tampered disclosure, wrong
issuer/scope/holder/audience, expiry, revocation, replay, refused consent,
unknown authority, stale snapshot, and draft-22 boundary shapes. Every
fixture is labelled `synthetic` with the profile version; nothing here
constitutes an interoperability certification.

## 8. Approval

- [ ] Independent review under SOV-037 before real-data provisioning/processing; synthetic work may proceed against the selected contracts without claiming interoperability qualification.
- [ ] Library conditions 1-4 evidenced in SOV-004/SOV-036 (v0.5: conditions 1 and 4 pass; 2 and 3 pass at the artifact layer plus the Sovra protocol corpus — external conformance suites still not run, see section 12).
- [ ] Record revision on any profile, algorithm, library, or value change.

## 9. G1 issuance implementation note (v0.2 revision)

SOV-009 implements the issuance control plane now; the walt-id SD-JWT VC
layer lands only after SOV-036 passes conditions 2-4. Until then the
encoder seam (`CredentialEncoder`) ships a synthetic JWT that is
deliberately not an SD-JWT VC:

- Content type `vnd.sovra.synthetic-credential+jwt`, body carries
  `synthetic: true` plus profile label `sovra-g1-synthetic/0.2`.
- Issuer `https://sovra.example/issuers/synth-1`, single ES256 key
  (`synth-1`, version 1), claim allowlist exactly `{adultOver18: true}`
  for `vct` `https://sovra.example/vct/adult-status/1`.
- The dev private key is the P-256 scalar 1 (public half is the curve
  generator), held in signer memory, never persisted or exported, armed
  only by two explicit flags. Anyone can recompute it, which is why it
  must never leave synthetic use.
- Migration V6 seeds genesis trust snapshot v1 authorizing the synthetic
  issuer only (scope `synthetic-only`, two distinct system identities
  keeping the maker/checker shape). Production supersedes v1 through the
  normal two-person flow; activation only moves forward.
- Cutover: `WaltIdSdJwtVcEncoder` replaces the synthetic encoder behind
  the same interface once SOV-036 passes. No call-site changes.
- Verifiers must reject the synthetic content type outside synthetic
  use; this is enforced when the verifier lands (SOV-010+), and the
  genesis scope marker plus artifact labels exist for that check.

Nothing in this note weakens the frozen profile above: it sequences the
build, and the synthetic artifact satisfies no interop claim.

## 10. Profile qualification sequencing (v0.3 revision)

SOV-036 is mandatory G1 library/profile qualification, not optional expanded product scope.
It qualifies the selected issuer/verifier/format adapters using independent fixtures before SOV-010/011 integration is accepted.
It does not depend on the final whole-product SEC suite or holder-custody release, which would create a circular implementation gate.
SOV-041 subsequently exercises the actual packaged consent-to-verification path, and SOV-032/034 retain full integrated/independent release assessment.
Library coordinates and protocol versions remain candidates until their source, support, dependency/provenance, Java 25 and exact-profile tests pass.
An available `.sha1` file is not a substitute for an independently trusted artifact origin and strong digest/provenance policy.

## 11. SOV-036 artifact-layer qualification (v0.4 revision)

SOV-036 qualifies the SD-JWT VC artifact layer now; the OpenID4VCI /
OpenID4VP protocol flows stay sequenced work. Nothing here claims
protocol-flow conformance, third-party wallet interop, or independent
review — those remain open with the owners named below.

### 11.1 Condition verdicts

| Condition (section 3) | Verdict | Evidence |
| --- | --- | --- |
| 1. Artifact registry | Pass | Pinned `id.walt.sdjwt:waltid-sdjwt-jvm`, `id.walt.openid4vci:waltid-openid4vci-jvm`, `id.walt.protocols:waltid-openid4vp-verifier-jvm`, all v1.2.0, from `https://maven.waltid.dev/releases` with releases-only, snapshots-disabled, checksum-fail repository policy (`backend/pom.xml`). |
| 2. Conformance + adversarial corpus | Partial: artifact layer only | Sovra adversarial corpus passes (see 11.3). OpenID conformance suites are not run: no VCI/VP flows are implemented yet, so there is nothing conformant to claim. No third-party wallet/issuer/verifier fixtures yet. |
| 3. License / transitive / support review | Partial: exercised path only | Resolved closure reviewed: walt-id modules Apache-2.0 via parent chain, transitive BSD-3-Clause/JNA-dual acceptable, no snapshot in the resolved graph (`id.walt.mdoc-credentials` excluded: it drags `org.cose:cose-java:1.1.1-WALT-SNAPSHOT`, and mDL is outside section 1). Community-edition API coverage is confirmed for the exercised SD-JWT path only; the pinned VCI/VP modules are unexercised. Nimbus 10.3 wins over walt-id's transitive 10.10 by nearest-first resolution, with an API-compatibility test pinning the 10.10 surface walt-id compiled against. |
| 4. Java 25 packaged behavior | Pass | Docker build on Temurin 25 plus the packaged two-instance e2e suite passing in both profiles (see 11.3). |

Strong digest pinning beyond repository checksums is still open:
Maven resolves by version from a releases-only repository, not by
caller-pinned artifact digest. Recording this as a residual gap, not a
pass.

### 11.2 Adapters and seams

- `SovraIssuerCryptoProvider` bridges the constrained `IssuerSigner`
  into walt-id's `JWTCryptoProvider`: one authorized key, no extra
  headers, no verify path. Refusals are tested, including zero signer
  calls on refusal.
- `WaltIdSdJwtVcEncoder` mints profile `sdjwt-vc`, type `dc+sd-jwt`,
  ES256 only, holder `cnf` binding, `adultOver18` disclosure, and the
  section 2 `vct` allowlist (`SOVRA_PROFILE=sdjwt-vc`; default stays
  `synthetic`).
- `WaltIdArtifactVerifier` verifies against the registered trust key —
  never a key from the artifact — then runs the same shared gates as
  the synthetic path (consent approval/expiry, credential expiry,
  status freshness, trust snapshot, holder binding, audience/nonce)
  with the same reason-code vocabulary.
- The profiles are mutually exclusive by test: neither parser accepts
  the other's artifacts.
- Decision receipts store the evaluated profile (`V10__decision_profile`,
  `sovra-g1-synthetic/0.2` / `sovra-g1-sdjwt-vc/0.2`) so a mixed fleet
  cannot mislabel stored evidence.

### 11.3 Validation evidence

- `WaltIdSdJwtTests` (5): constrained-signer round trip, disclosure
  digests recomputed with JDK SHA-256 independently of walt-id's walk,
  provider refusals, claim allowlist, Nimbus 10.3 compatibility.
- `WaltIdVerificationParityTests` (10): walt-path acceptance, mutual
  exclusion, freshness/trust/outage/binding parity with the synthetic
  path, JWT tamper, disclosure tamper, stripped disclosures
  (`CLAIMS_MISMATCH`), byte-identical replay.
- `WaltProfileIssuanceTests` (4): full HTTP consent-to-verification
  under `sovra.profile=sdjwt-vc`, artifact shape, tamper rejection.
- `scripts/e2e-verification.py`: PASS in both profiles (two instances,
  real PostgreSQL, concurrency, negative matrix, restart and DB-restart
  recovery, audit/decision consistency); the script asserts the
  decision profile label matching `SOVRA_PROFILE`.
- Full backend suite: 281/281 green on Java 25.

### 11.4 Sequenced deviations from section 1 (recorded, not silent)

The frozen table in section 1 still defines "done". The following are
built later, in this order, and every receipt until then names the
profile that actually evaluated it:

1. Holder binding is Sovra's `sovra-presentation/v1` consent-bound
   ECDSA proof, not `kb+jwt`. KeyBinding JWT arrives with the
   OpenID4VP presentation flow.
2. No OpenID4VCI flows yet (`pre-authorized_code`, `authorization_code`)
   and no OpenID4VP transport yet (`direct_post.jwt`); issuance and
   consent run over Sovra's own versioned APIs (SOV-009/010/011 scope).
3. Third-party wallet/issuer/verifier fixtures and the applicable
   OpenID conformance suites run once flows 1-2 exist.
4. Independent review (SOV-037) stays the gate before real-data
   provisioning/processing.

## 12. SOV-036 protocol-layer qualification (v0.5 revision)

SOV-036 now qualifies the G1 OpenID4VCI / OpenID4VP protocol layer
against Sovra's own corpus: an independent Nimbus-only wallet,
third-party issuer fixtures, DCQL matching, and VCI/VP adversarial
suites. Section 11.4 items 1-3 are implemented at this level;
nothing here claims external conformance-suite certification,
production wallet interop, or independent review — those remain
open with the owners named below. Full evidence is recorded in the
[protocol assessment](../../engineering/sov-036-protocol-assessment.md).

### 12.1 Condition verdicts

| Condition (section 3) | Verdict | Evidence |
| --- | --- | --- |
| 1. Artifact registry | Pass (unchanged) | Same pinned v1.2.0 coordinates and releases-only policy as 11.1; no new dependencies. |
| 2. Conformance + adversarial corpus | Partial: artifact layer + Sovra protocol corpus | 68 protocol tests green (see 12.3): VCI pre-authorized/authorization-code flows, `direct_post.jwt` with pinned ECDH-ES+A256KW/A256GCM transport, `kb+jwt` binding, DCQL fulfillment, replay/expiry/downgrade/foreign-issuer negatives. The applicable OpenID conformance suites are still not run: they need networked registered deployments outside this environment. No production-wallet interop is claimed. |
| 3. License / transitive / support review | Partial: exercised path only | Exercised protocol path adds no new dependency: Sovra-owned transports over Nimbus JOSE 10.3 (the section 3 substrate) plus the qualified walt-id SD-JWT classes (`SDJwt`, `KeyBindingJwt`). The pinned `waltid-openid4vci-jvm` issuer-side endpoint handlers and `waltid-openid4vp-verifier-jvm` verifier2 session machinery remain unexercised (see 12.2); their Community-edition API coverage is still unconfirmed. |
| 4. Java 25 packaged behavior | Pass | Full backend suite 460/460 green on Java 25; the two-instance packaged e2e suites pass in both profiles (see 12.3). |

Strong digest pinning beyond repository checksums is still open
(recorded in 11.1, unchanged).

### 12.2 Adapters, seams, and the session-handler decision

- `VciService` / `VciController` implement the G1 OpenID4VCI
  subset: issuer metadata, operator-published `pre-authorized_code`
  offers, a synthetic authorization server (`authorization_code`
  with PKCE S256), token redemption, `c_nonce` rotation, and the
  credential endpoint delegating to `IssuanceService.issueVci` —
  identical trust, allowlist, key, idempotency, and audit gates
  as native issuance. Codes, tokens, and nonces are 256-bit
  CSPRNG values stored as hashes, 5-minute single-use
  (`V16__openid.sql`, `V17__openid_resolvers.sql`).
- `VpService` / `VpController` implement the G1 OpenID4VP subset:
  RP-opened sessions serving signed request objects (ES256,
  DCQL query, `response_mode=direct_post.jwt`), JWE-encrypted
  responses to the verifier key, submission-shape and DCQL
  fulfillment checks, then delegation to `VerificationService`
  — identical consent, freshness, trust, replay, and audit
  gates as native verification. Plain `direct_post` is
  rejected outside loopback harness runs.
- `KeyBindingVerifier` verifies RFC 9901 section 8 KeyBinding
  JWTs through the qualified walt-id `KeyBindingJwt` interface
  against the `cnf` holder key, with Sovra-owned header pins
  (`alg` ES256, `typ` `kb+jwt`), the section 4 freshness
  window, and a JDK-recomputed `sd_hash`. The `sdjwt-vc`
  profile binds with `kb+jwt`; the `synthetic` profile keeps
  the Sovra proof message.
- `Dcql` builds the verifier query and matches format, `vct`
  allowlist, and disclosed claim paths/values for the G1
  single-credential profile; multi-credential shapes are
  rejected, not partially evaluated.
- `OpenIdKeys` holds the synthetic P-256 verifier key (scalar
  2, memory-only, same two-flag arming as the issuance
  scalar 1) for request-object signing and response
  decryption, served publicly as JWKS.
- Session-handler decision (recorded, not silent): walt-id
  1.2.0 ships issuer-side VCI endpoint handlers and VP
  verifier2 session machinery, but they carry their own
  session/token stores, coroutine runtime shape, and crypto
  providers that would bypass Sovra's control plane
  (authorization decisions, trust snapshots, audit events,
  idempotency records, RLS tenancy, the constrained signer).
  Adopting them is re-triage work under SOV-037, not a
  drop-in swap: the G1 transports stay Sovra-owned over the
  section 3 Nimbus substrate, with format and binding
  verification through the qualified walt-id SD-JWT
  interfaces. The pinned VCI/VP modules remain dependencies
  so the selection stays convertible.

### 12.3 Validation evidence

- `VciFlowTests` (10): metadata, both grants, single-use
  `c_nonce` proofs, nonce rotation after failed proof,
  VCI-to-ACCEPTED consent circle, RBAC.
- `VciConformanceTests` (14): grant confusion, expiry,
  audience/key/alg proof forgeries, replay, unknown
  configuration/format/proof-type, batch rejection, token
  abuse, wallet-call audit.
- `VpFlowTests` (10): signed request objects verified
  against the JWKS, encrypted-response acceptance,
  byte-identical replay, wrong-nonce binding rejection,
  pending-consent rejection, plain-post/JWE-tamper/state/
  expiry rejections, RBAC.
- `VpConformanceTests` (12): wrong-key/truncated/downgraded
  JWEs, missing binding, wrong-type/tampered-hash/
  audience-confused bindings, cross-session replay,
  submission mismatch, foreign-issuer and tampered-
  disclosure presentations.
- `KeyBindingTests` (6), `DcqlTests` (11),
  `OpenIdKeysTests` (3), `ThirdPartyFixturesTests` (2):
  independent-wallet binding qualification, DCQL unit
  coverage, verifier-key round trip, checked-in third-party
  issuer key pinned to the minting key.
- `WaltIdVerificationParityTests` (10) and
  `WaltProfileIssuanceTests` (4) now drive KeyBinding
  proofs in the `sdjwt-vc` profile.
- `scripts/e2e-verification.py`: PASS in both profiles
  (two instances, real PostgreSQL, concurrency, negative
  matrix, restart and DB-restart recovery); the script
  builds profile-matching bindings (Sovra message under
  `synthetic`, `kb+jwt` under `sdjwt-vc`).
- Full backend suite: 460/460 green on Java 25.
- Implemented contract 0.7.0
  (`docs/engineering/implemented-api.openapi.yaml`).

### 12.4 Remaining deviations from section 1 (recorded, not silent)

1. External OpenID conformance suites are not run
   (networked registered deployments; infeasible in this
   environment). Interop is evidenced by the independent
   Nimbus wallet, third-party fixtures, and the Sovra
   adversarial corpus only.
2. Walt-id VCI issuer-side endpoint handlers and VP
   verifier2 session machinery are pinned but unexercised;
   adopting them (or re-confirming the Sovra-owned
   transports) is SOV-037 re-triage input.
3. Strong artifact-digest pinning beyond repository
   checksums is still open (from 11.1).
4. `invalid_token` at the credential endpoint answers
   HTTP 400 with the OAuth2 error shape (uniform with the
   other wallet errors) rather than HTTP 401; recorded G1
   simplification.
5. Independent review (SOV-037) stays the gate before
   real-data provisioning/processing.
