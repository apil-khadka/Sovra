# Standards, evaluation and open research

## Primary standards and guidance to verify in implementation

- W3C Verifiable Credentials Data Model v2.0 — https://www.w3.org/TR/vc-data-model-2.0/
- OpenID for Verifiable Credential Issuance 1.0 — https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
- OpenID for Verifiable Presentations 1.0 — https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- IETF SD-JWT — https://www.rfc-editor.org/rfc/rfc9901.html (confirm status/relationship to SD-JWT VC profiles before relying on it)
- OpenID Federation 1.0 — https://openid.net/specs/openid-federation-1_0.html
- FATF Digital ID guidance — https://www.fatf-gafi.org/en/publications/Financialinclusionandnpoissues/Digital-id-guidance.html
- EUDI Wallet initiative — https://digital-strategy.ec.europa.eu/en/policies/eudi-wallet-implementation
- MOSIP — https://docs.mosip.io/
- Azure Mission-Critical architecture principles — https://learn.microsoft.com/en-us/azure/well-architected/mission-critical/

These URLs are leads to primary resources from existing design research; they are **not** a claim that each current revision was re-verified for this documentation snapshot. Confirm versions, licenses, security guidance and interoperability profiles before building.

## Research questions

1. Which credential format is minimal but convincingly standards-adjacent for an eight-day demo?
2. Can issuer schemas be adapted without manually coding per-country adapters? What are the correctness limits?
3. Can agent outputs cite exact source text, not invented policy authority?
4. What functionality do existing EUDI wallet, MOSIP, identity orchestration and VC stacks already cover? Avoid calling existing features inventions.
5. Which details of Nepal identity rules, Australia AML/CTF and GDPR are truly applicable to a hypothetical system? Do not claim formal compliance based on general summaries.

## Proposed evaluation matrix

| Case | Expected |
|---|---|
| Known schema + valid policy | Valid proposed plan, proof accepted only after consent and crypto checks |
| Unknown third schema with compatible field | Planner finds viable mapping, cites exact source |
| Unknown third schema with incompatible assurance | No valid plan or manual review, no false acceptance |
| Overbroad request for passport image | Policy gate rejects unapproved/unnecessary disclosure |
| Forged policy citation | Guard rejects unsupported source passage |
| Tampered credential | Crypto check fails |
| Revoked credential | Status check fails |
| Replay old proof | Replay cache rejects |
| Wrong audience | Verifier rejects |
| Model unavailable | Safe fallback: dynamic planning unavailable |
| Prompt injected issuer metadata | No unauthorized action or secret disclosure |

Measure plan-validity rate, grounded-citation precision, false-accept rate (target zero across fixtures), sensitive field count per presentation, e2e latency, and baseline difference against a static mapping engine. Publish fixture set and reproducible scripts if permitted.
