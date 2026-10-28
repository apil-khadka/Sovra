# SOV-001: proof profile decision record

**Version:** 0.2 (proposed G0 decision, pending independent review).
**Date:** 2026-10-28 (v0.1); revision note 2026-10-28 (v0.2, section 9).
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

- [ ] Independent security review of this record (required before SOV-005/SOV-008 start).
- [ ] Library conditions 1-4 evidenced in SOV-004/SOV-036.
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
