# Synthetic fixture and API example index

These files are **documentation examples**, not executable ground truth and not an official W3C VC/SD-JWT/OID4VP wire profile. Keep all identifiers fictional, signatures absent, and data synthetic. Implement canonical runtime contracts in code and test consistency between code and docs.

- `mock-issuer-np.json`: simulated issuer metadata with allowed credential scopes.
- `mock-issuer-third-jurisdiction.json`: intentionally unfamiliar schema for *evaluation*; no country-specific model prompt rule.
- `mock-relying-party-policy.json`: fictional RP disclosure policy.
- `candidate-plan.example.json`: AI output schema example; must go through deterministic guard before a proof is requested.

Do not expose evaluated third-country gold answers to the model prompt or add a fixture-specific adapter. Scope the hidden test corpus separately before recording scores.
