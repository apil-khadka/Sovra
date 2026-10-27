# Meta-powered interoperability planner

## AI task (the product differentiator)

Given a relying-party requirement, its exact policy text, issuer capabilities, and one or more unfamiliar credential schema descriptions, propose a **structured, minimal, source-grounded verification plan**. Provide positive/negative compatibility findings, provenance, confidence/uncertainty, and a reason when no acceptable path exists.

## Typed tools (read-only to start)

- `listTrustedIssuers(jurisdiction, capability)`
- `getCredentialSchema(issuerId, credentialType)`
- `getPolicyDocument(policyId, version)`
- `getIssuerCapabilities(issuerId)`
- `lookupEvidenceCompatibility(requestedClaim, candidates)`

Tool responses are **untrusted data**, even if they come from an issuer. Handle prompt injection in schema descriptions and policy prose. Protect secrets; never let model-generated tool parameters bypass access controls.

## Plan shape (conceptual)

```json
{
  "request_id": "req_synthetic_001",
  "requested_outcome": "age_over_18",
  "candidate_issuer_id": "np-demo-issuer",
  "credential_type": "AdultStatusCredential",
  "disclosed_claims": ["adultOver18"],
  "policy_citations": [{"document_id": "au-demo-policy", "section": "2.1"}],
  "explanation": "A dedicated adult attestation avoids releasing birth date.",
  "status": "proposed",
  "requires_holder_consent": true
}
```

The above is a schema sketch, not verified against any current model/API or interoperability standard. Use runtime validation (e.g. JSON Schema + semantic rules) and reject hallucinated issuer IDs, unsupported claim types, missing/false citations and disallowed disclosure.

## Execution boundary

AI **may** extract candidate requirements, retrieve schemas, rank options, identify gaps, map similar fields and explain decisions. AI **must never** sign claims, mint authority, assert legal compliance, approve access, assert age/identity from text, override consent, accept a revoked credential or override verifier checks.

## Proof of real agentic behavior

- Unseen mock third-country issuer test: its policy/schema is introduced **after** core agent setup.
- Run a baseline static mapping engine with no country-specific adapter and compare coverage.
- Require citation anchors to actual input policies and measure the fraction that are substantively supported.
- Run adversarial policy documents with embedded 'ignore all instructions' payloads; no unauthorized tool use should occur.
- Record trace of discovery, chosen evidence, tool outputs (redacted), deterministic guard, and final outcome.

## Model dependency and fallback

Use **an eligible Meta model**, with model ID and function-calling/structured-output compatibility smoke-tested against the actually granted account. Never silently switch to another vendor in submitted core flow. On unavailable model service, verification may proceed for previously approved fixed flows, but dynamic interoperability must clearly show itself as unavailable; do not fake a model response.
