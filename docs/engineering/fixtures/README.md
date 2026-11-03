# Synthetic fixture and API example index

These files are **documentation examples**, not executable ground truth and not an official W3C VC/SD-JWT/OID4VP wire profile. Keep all identifiers fictional, signatures absent, and data synthetic. Implement canonical runtime contracts in code and test consistency between code and docs.

- `mock-issuer-np.json`: simulated issuer metadata with allowed credential scopes.
- `mock-issuer-third-jurisdiction.json`: intentionally unfamiliar schema for *evaluation*; no country-specific model prompt rule.
- `mock-issuer-synth2.json`: second synthetic issuer attesting the governed fjord/harbor compatible schemas plus the explicitly incompatible employment-tenure schema (mirrors `DualIssuerFixtures`).
- `mock-relying-party-policy.json`: fictional RP disclosure policy.
- `candidate-plan.example.json`: AI output schema example; must go through deterministic guard before a proof is requested.
- `candidate-plan-mapped.example.json`: mapped-policy unfamiliar-schema plan example (fjord `isAdult` under `age-check-mapped` v1, guard `sovra-guard/2`).
- `dual-issuer-provisioning.md`: exact two-person trust payloads, per-node signing config/refusal behavior, discovery cases, and the two-database sovereignty disclaimer.

Do not expose evaluated third-country gold answers to the model prompt or add a fixture-specific adapter. Scope the hidden test corpus separately before recording scores.
The runtime authority is the versioned `ApprovedSchemas` registry in code plus the active trust snapshot — never these example files and never model-authored text.
