# First implementation vertical slice: hours 0–24

**Purpose:** prove feasibility before creating lots of services or screens. This is a build plan, not an implemented artifact.

## Commit sequence

1. **Freeze the demo contract:** choose `age_over_18`, fictional RP policy v1, `AdultStatusCredential`, one issuer trust record, and `VERIFIED_EVIDENCE | REJECTED | MANUAL_REVIEW` outcomes. Document whether profile is demo JWT/JWS or a fully interoperable VC flow.
2. **Run the actual Meta model smoke test:** account credentials from environment variables only; confirm model availability, structured response or tool capability, and a bounded JSON candidate. Record actual model ID (not from memory), response ID, latency and token counts; redact sensitive values.
3. **Minimal crypto fixture:** trusted issuer signs a synthetic `adultOver18: true` credential via a vetted library, verifier checks fixed issuer key/scope, signature, validity and status. Add tampering test *first*.
4. **Single guard:** a candidate request proposing `passportImage` instead of signed adult evidence is rejected, even if produced by model. Test invented issuer and absent policy citation.
5. **Session authorization:** RP creates audience/nonce/expiry; wallet UI explicitly consents; sign or otherwise cryptographically bind holder proof to nonce/audience; verifier consumes one-time challenge. Test replay and wrong audience.
6. **Connect agent discovery:** it reads the public synthetic policy and issuer schema through scoped tools; creates a candidate mapping and citation; validation checks both.
7. **Record a one-minute fresh checkout demo:** valid, then tampered or replayed, plus evidence of live Meta model planning. Only then add second country and polished UI.

## Definition of ready before parallel agents

- Shared types/JSON schemas and error code table exist.
- One cross-process test harness exists, with deterministic fixture clock where practical.
- No service assumes source country databases are globally reachable.
- Model API key is never embedded in prompts, fixtures or Git history.
- Every model-generated plan is `UNAPPROVED` until the validator checks it.

## Stop condition

If no end-to-end trusted, signed evidence by end of Oct 29, do not add a third country or complex UX. If no working Meta model call, do not simulate a model response in the submitted product; fix Meta integration first.
