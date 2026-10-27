# TrustMesh Software Requirements Specification (SRS)

**Version:** 0.2 candidate · **Date:** 2026-10-27 · **Scope:** hackathon MVP only.

## 1. Purpose

Test the viability and safety of policy-grounded AI planning across simulated, independent credential issuers. Deliver a public, reproducible, working demonstration—not a regulated identity service.

## 2. Actors

**Issuer admin:** provisions synthetic identities, authorizes and revokes attestations. **Holder:** receives stored signed attestations and explicitly approves each presentation. **Relying party (RP):** submits purpose, requested outcomes, approved policy, and receives verified-evidence result. **Federation admin:** curates allowed issuer/key/credential scopes in registry. **AI planner:** advisory typed-tool client with no power to sign or authorize. **Auditor:** examines privacy-preserving decision traces.

## 3. Functional requirements

| ID | Priority | Requirement | Observable acceptance evidence |
| --- | --- | --- | --- |
| FR-01 | P0 | Independently configured issuer domains and keys | Two issuer instances have different key IDs, storage and configs |
| FR-02 | P0 | Issue synthetic, purpose-scoped signed attestation | Valid issuer signature verified; tamper test fails |
| FR-03 | P0 | Publish trusted issuer metadata and allowed credential scope | Unknown/unaccredited issuer rejected |
| FR-04 | P0 | RP submits purpose and proof outcome in structured intent | Invalid purpose/outcome rejected before AI execution |
| FR-05 | P0 | Meta AI discovers issuers, capabilities, schemas and cited policy sections | Real model usage trace with tool results and structured proposal |
| FR-06 | P0 | Deterministic guard rejects unsupported, overbroad and uncited claims | Over-disclosure/fictional issuer tests fail |
| FR-07 | P0 | Holder must affirm requested claim set and destination | Reject/timeout => no presentation |
| FR-08 | P0 | Verifier checks signature, issuer permission, expiry, status and presentation binding | Replay, wrong audience, forged signature, revoked all rejected |
| FR-09 | P0 | Audit output avoids private document text and identifying fields | Logs contain pseudonymous request IDs and reason codes only |
| FR-10 | P0 | Demo exposes live tool decisions and independent guard results | Show AI suggestion AND guard decision, no hidden scripted path |
| FR-11 | P1 | Unseen synthetic issuer mapping test | No bespoke adapter added after fixture reveal |
| FR-12 | P1 | Explicit manual-review state for uncertainty/outage | No false-positive verification when Meta model unavailable |
| FR-13 | P1 | Revocation UI with fail-closed high-assurance status handling | Credential valid then revoked then rejected |
| FR-14 | P2 | Official OID4VCI/VP conformance | Defer pending end-to-end conformant profile evidence |
| FR-15 | P2 | True SD-JWT VC/BBS selective disclosure | Do not represent field hiding as cryptographic disclosure |

## 4. Non-functional and security requirements

- **Confidentiality:** only synthetic identity profiles; no biometrics or real government IDs; never send identity records, private keys, bearer credentials or raw proofs to the model API.
- **Integrity:** pin accepted algorithms, validate JWT/JWS cryptographically through vetted libraries, validate claims against an approved issuer + scope + evidence policy matrix.
- **Fail safely:** model/tool/schema/policy errors return `PLAN_REJECTED` or `MANUAL_REVIEW`; registry/status outages cannot become successful verifications.
- **Replay:** a verifier-issued, single-use challenge is bound to audience and plan and consumed atomically. Issuance-nonce mechanisms are distinct from presentation replay defense.
- **Audit:** correlation IDs, provenance and structured outcome codes; redact PII and policy excerpts containing it.
- **Reproducibility:** one setup path, synthetic fixtures, automated tests and a 3-minute recorded working demo.
- **Performance:** instrument real latency (model call, tool count, plan validation and verification); do not invent an SLA.
- **Cost:** bound tool calls, tokens, concurrency and API spend; show safe fallback if credits/account unavailable.

## 5. Assumptions, constraints, non-goals

The team has at most four approved hackathon participants. Only eligible hackathon-period code belongs to the final demonstrated contribution. The program starts Oct 27 and closes Nov 4, 2026, at 9:00 PM Eastern. No production key management, nation-level accreditation, bank customer onboarding, sanction screening, legal advice or geographic residency guarantee in P0.

## 6. Critical acceptance scenario

Given a fake RP with an approved `age_over_18` policy and trusted demo Nepal issuer, when the Meta agent reads its schema and proposes `AdultStatusCredential` and the wallet holder approves, then the verifier validates a *freshly challenge-bound* presentation and returns `VERIFIED_EVIDENCE` plus `NOT_DETERMINED` for legal KYC. If issuer status becomes revoked, the identical scenario must return `REVOKED`.

## 7. Open decisions

The team must adopt or explicitly defer holder-binding proof, a formal VC/VP profile, issuer status freshness policy, and signed manifest governance. See the architecture ADRs and the private decision tracker.
