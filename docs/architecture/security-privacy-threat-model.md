# Security and privacy requirements

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

## Compliance truthfulness

Residency of authoritative source records is different from residency of every consented disclosure, operational log or model-input trace. Legal KYC/AML sufficiency depends on actual jurisdiction and regulated entity; a signature verifies issuance integrity, not necessarily proofing assurance or sufficiency for CDD. Use only synthetic profiles and public/example policy documents in the hackathon.
