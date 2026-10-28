# Live planning integration (SOV-013)

**Status:** fixture mode implemented and tested; live acceptance is NOT
claimed. OD-02 stays open until the smoke procedure below passes against
verified no-charge Meta capacity.

## Adapter

Live planning uses Spring AI's OpenAI-compatible chat adapter
(`spring-ai-starter-model-openai`) pointed at the operator-configured
chat endpoint. The Meta Llama API speaks that contract; no vendor SDK
is embedded, and no endpoint, model id, or key has a default anywhere
in the repo — every one arrives from the environment (see
[PlanningProperties](../../backend/src/main/java/dev/sovra/planning/PlanningProperties.java)):

| Variable | Meaning |
| --- | --- |
| `SOVRA_AI_LIVE_ENABLED` | Arming flag; live calls happen only when `true` |
| `SOVRA_AI_BASE_URL` | Operator-configured chat endpoint |
| `SOVRA_AI_MODEL` | Account-verified model id |
| `SOVRA_AI_API_KEY` | Provider credential, never logged or returned |

Spring AI's OpenAI autoconfigurations stay excluded in
`SovraApplication`, so default boot is keyless and serves
explicitly-labeled fixture candidates (`mode: FIXTURE`,
`liveAcceptance: false`, `model: none (fixture)`).

Optional budgets (defaults in parentheses): `SOVRA_AI_MAX_TOOL_CALLS`
(8), `SOVRA_AI_TIMEOUT` (10s), `SOVRA_AI_MAX_RETRIES` (1),
`SOVRA_AI_MAX_TOKENS` (2000), `SOVRA_AI_MAX_PROMPT_CHARS` (8000),
`SOVRA_AI_TEMPERATURE` (0.0), `SOVRA_AI_SEED` (7).

## Fixture versus live

- Fixture mode proves wire-shape compatibility with the deterministic
  guard only. It never satisfies live acceptance:
  `PlanningService.requireLive` and `PlanningEvaluator.scoreLive`
  reject fixture results, and the evaluation harness records the agent
  arm as not-live until a verified live run exists.
- When live planning is armed but the provider is unreachable, slow,
  throttling, or returns malformed output, proposals fail explicitly
  with 503 (`planning_unavailable`, retryable) — never a silent
  fixture fallback and never invented evidence. Previously approved
  fixed flows are unaffected.
- `GET /api/plans/status` reports `mode`, `liveEnabled`, and
  `modelConfigured` as booleans only; endpoint, model, and credential
  values never leave the server.

## Tool bounds

Exactly five read-only discovery tools exist
(`listTrustedIssuers`, `getCredentialSchema`, `getPolicyDocument`,
`getIssuerCapabilities`, `compareEvidence`). Every callback
reauthorizes the live caller against `PROPOSE_PLAN`, validates
arguments against allowlists (unknown members, oversized values, and
authority-smuggling members fail), charges the per-request call
budget, and reads only the active trust snapshot plus the frozen G1
policy documents. Tools take no URLs, make no network calls, perform
no writes, cannot create policy authority, and return minimized
metadata — never keys, tokens, credentials, or proofs. Model output is
strictly parsed into the guard plan shape and bounded in size before
it becomes a candidate.

## Frozen versions

Every proposal and evaluation run records `sovra-planner-prompts/1`,
`sovra-planner-tools/1` plus the SHA-256 tool-schema hash,
`sovra-baseline-planner/1`, the model id, the seed, tool-call counts,
and sanitized latency/token evidence (cost is `unreported` unless the
provider reports it). The committed tests pin the tool-schema hash,
so any tool-contract drift fails loudly.

## No-charge verification checklist (before arming live)

1. Confirm the account's no-charge grant, quota, and hard spend cap in
   the provider console; screenshot the cap for the evidence pack.
2. Set `SOVRA_AI_LIVE_ENABLED=true` with the endpoint, model, and key
   from a secret store (never the repo), and a restrictive timeout.
3. Run the smoke procedure below with synthetic inputs only.
4. Confirm `GET /api/plans/status` reports `LIVE` and the smoke run
   records the actual model id, prompt/tool versions, token usage,
   latency, and guard verdicts — including failures.
5. Disable the key or set spend alerts immediately after; record the
   sanitized run log as the OD-02 evidence.

## Smoke procedure (OD-02)

With live armed against verified no-charge capacity:

1. `POST /api/plans/propose` with the age-over-18 synthetic intent and
   the frozen policy binding; expect a `LIVE` candidate with citations
   to the exact versioned sources.
2. `POST /api/plans/propose` with an unknown outcome and an invented
   claim; expect 400 before any model contact (no provider call fires).
3. `POST /api/guard/validate` for the live candidate; record accept or
   the explicit rejection code — the guard stays authoritative.
4. Revoke the provider key mid-run (or point at an unreachable host);
   expect explicit 503 with no candidate and no fixture fallback.
5. Run the frozen corpus through `PlanningEvaluator` and compare the
   live agent arm against the recorded baseline arm, failures
   included; freeze the full result record with model id, prompt/tool
   versions, seed, token usage, and latency.

A failed or blocked model is never replaced by a pre-recorded
response. Fixture runs stay labeled fixture runs.
