# Security and privacy requirements

The selected backend is [Java 25 LTS with Spring](java-spring-baseline.md).
The [security validation plan](../engineering/security-validation-plan.md) expands this threat model into proposed adversarial cases and production evidence gates.
These are requirements, not claims that the Java implementation or security assessments have been completed.
The [mission-critical security research](../research/security-and-mission-critical-review.md) examines operator/build compromise, replay-safe recovery, issuer-local failover, key-copy/cache exposure, and validation priorities against primary sources.

## Mandatory checks

- Use established crypto and JWT/VC libraries; do not write a novel signature scheme.
- Protect issuer private keys, provide per-issuer rotation and explicit key identifiers.
- Verify exact issuer trust metadata and key binding, algorithms and critical headers.
- Validate payload schema, validity period, status/revocation, holder binding where appropriate, nonce/challenge, audience, expiry and one-time replay protection.
- Bind authorization to the **specific** requested claims and relying party, not a broad blanket consent.
- Partition logs by purpose and redact policy/context containing PII.
- Guard model tool calls and outputs with schema validation, allowlists and consent; prompt instructions embedded in external documents are hostile input.

## Threat matrix

| Threat | Mitigation / test |
|---|---|
| Model hallucinates issuer/policy | Validate IDs, fetch policy text, verify section citations |
| Malicious issuer metadata instructs agent to leak data | Treat source text as data only, scoped tool privileges, prompt-injection test |
| Credential tampering | Signature verification fails |
| Issuer key substitution | Registry trust-anchor/key authorization check |
| Credential revoked | Online status verification fails closed for high assurance |
| Proof replay | Unique nonce and per-verifier replay cache |
| Wrong relying party | Audience/client-binding verification |
| Excessive fields requested | Allowlist plus consent, reject overbroad disclosure |
| Credential claims exposed to model logs | Restrict model inputs to schemas and non-PII plan context |
| Cross-tenant/country record access | Independent configs/data stores plus isolation tests |
| Country-node unavailable | Defined 'unable to verify now' state, never auto-approve |

## Privileged, processing and recovery threat boundaries

The business SRS requires phishing-resistant privileged authentication and recovery, bounded elevation and independent approval for designated high-impact changes.
Ingestion, OCR, review, signing, decryption, deployment, migration and audit identities must have separate scoped authority.
The signer must validate authorized issuance context instead of offering an arbitrary signing oracle.
Runtime database roles must not be owners, superusers or possess BYPASSRLS; pooled connection context and alternate service entry points need adversarial tests.

Hostile image parsing requires process/OS/runtime isolation, resource limits and restricted egress outside the Java security model.
The deployment threat assessment must identify ultimate cloud/host/root override powers and decide whether attested confidential processing is necessary for the approved sensitive-data boundary.
Encryption at rest alone does not meet a requirement to hide plaintext from a compromised authorized processing host.

Backups and independent restored keys are separate authority-bearing copies.
Recovery must fence obsolete writers and reconcile or invalidate ambiguous consumed challenges, revocations, trust epochs and approvals before acceptance resumes.
Known denied access cannot gain silent extension through token, grant, positive-permission or DEK caches; their explicit bounds and active-job containment must be tested.
Key disablement alone does not recall plaintext or already cached keys.

Production artifact admission must bind approved source, builder/provenance, digest, configuration and runtime identity.
Readiness must reflect actual authority freshness, replay persistence, authorization/key availability and required durable audit, including when superficial HTTP health remains green.
The required [SEC and MC scenarios](../engineering/security-validation-plan.md) cover these threats under synthetic load, restore, rollback, alternate ingress and provider control/data-plane failures.
The [backlog](../engineering/implementation-backlog.md) records implementation ownership roles and dependencies; all controls remain unimplemented until evidence exists.

## Compliance truthfulness

Residency of authoritative source records is different from residency of every consented disclosure, operational log or model-input trace. Legal KYC/AML sufficiency depends on actual jurisdiction and regulated entity; a signature verifies issuance integrity, not necessarily proofing assurance or sufficiency for CDD. Use only synthetic profiles and public/example policy documents in the hackathon.
