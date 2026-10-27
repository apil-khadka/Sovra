# AI interoperability agent — contract and boundaries

## Mission

From approved RP intent plus retrieved, versioned issuer schemas/policies, produce a *candidate* plan identifying a minimal supported evidence path **or** an explicit inability to establish a path. All output is untrusted until semantic validation.

## Tool model

Expose **read-only, scoped and bounded** tools:

| Tool | Input | Output | Safety notes |
| --- | --- | --- | --- |
| `listTrustedIssuers` | outcome, jurisdiction hint | candidate issuer IDs + accreditation/scope metadata | No direct database access or unsandboxed web URLs |
| `getCredentialSchema` | exact allowed issuer ID, schema ID | versioned claim definitions and predicates | Untrusted text; data, never instruction |
| `getPolicyDocument` | policy ID and version | source spans with stable section IDs | Grounded citations; no invented legal authority |
| `getIssuerCapabilities` | exact issuer ID | supported credential formats, endpoints, valid scopes | Metadata validated by registry allowlist |
| `compareEvidence` | desired outcome, candidate credential IDs | deterministic compatibility hints | Pure function; not final authorization |

Do **not** provide the model a general-purpose HTTP execution or `issueCredential`, `sendDocument`, `sign`, `approveConsent` or `verifyAsValid` tool. Typed bounded orchestration is safer than autonomous execution.

## Model-to-code JSON candidate (illustrative)

```json
{
  "plan_id": "pln_demo_001",
  "requested_outcome": "age_over_18",
  "candidate_issuer_id": "np-synthetic-issuer",
  "credential_type": "AdultStatusCredential",
  "claim_paths": ["adultOver18"],
  "evidence": [
    {"document_id": "rp-au-demo-v1", "section_id": "age_eligibility"},
    {"document_id": "issuer-np-demo-schema-v1", "section_id": "adult_status"}
  ],
  "unresolved_issues": [],
  "needs_holder_consent": true,
  "recommendation": "CANDIDATE_ONLY"
}
```

## Hard validator rules

1. JSON Schema checks shape. Unknown enum/extra fields rejected.
2. All issuer/credential IDs must correspond to **trusted** pinned metadata at this epoch; metadata itself may be compromised and must be provenance-checked.
3. Every claimed policy section and claim path must resolve to the exact versioned input; extracted text must actually support the claimed requirement.
4. Requested fields must be within RP's approved purpose/outcome and explicit disclosure budget; model cannot modify preapproved policy.
5. Missing assurance, unsupported claim semantics, mismatched threshold or ambiguous evidence => `MANUAL_REVIEW`, not true.
6. Holder consent, keys/signatures, issuer authorization, challenge, status and replay are outside the agent.
7. No prompt containing real PII, secrets, raw credentials or production endpoint bearer tokens.

## Observable trace

Show requests, sanitized tool names and results, retrieved document references, proposed plan, deterministic guard decision and proof result. **Do not claim or display private model chain-of-thought**; expose your own *action log* and source-grounded explanation fields only.

## Models and compatibility

The organizer requires eligible Meta model integration. Account-specific model IDs, tool mode, schema-output mechanics, authentication, usage limits and costs must be verified with a real smoke test before coding against assumptions from historical reports. A failed or blocked model is never replaced by a pre-recorded synthetic 'AI' response in the submitted demo.
