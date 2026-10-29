# Live planning integration (SOV-013)

**Status:** fixture mode implemented and tested. The smoke procedure
below PASSED against the Baseten hackathon grant on 2026-10-29 (see
evidence), and a Stage 5 re-verification run PASSED the same day with
fresh usage evidence; OD-02 remains partially resolved pending
console-verified no-charge limits, processing/retention terms and the
complete frozen live-evaluation corpus comparison.
Owner acknowledgement records evidence; it does not substitute for those checks.

## Adapter

The [2026-10-29 continuation guide](../engineering/continuation-guide.md) records remaining spend/retention/evaluation work and the uncommitted implementation baseline.
The documented smoke is prior technical evidence; it is not a provider billing-cap verification or permission for additional automatic live runs.

Live planning uses Spring AI's OpenAI-compatible chat adapter
(`spring-ai-starter-model-openai`) pointed at the operator-configured
chat endpoint. The recorded Baseten candidate was exercised through that adapter; this does not establish compatibility with every Meta/model endpoint.
No vendor SDK
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
`SOVRA_AI_MAX_TOKENS` (8000: reasoning consumes the output budget), `SOVRA_AI_MAX_PROMPT_CHARS` (8000),
`SOVRA_AI_TEMPERATURE` (0.0), `SOVRA_AI_SEED` (7).

## Hackathon endpoint (Baseten, OD-02 candidate)

Meta Global AI Developer Hackathon grant: $100 in Baseten credits
for Muse Spark Open at an OpenAI-compatible endpoint. Provenance
verified against the pinned client: Spring AI 2.0.2 delegates to
the OpenAI Java SDK 4.80.0, whose base URL carries the `/v1` prefix
(default `https://api.openai.com/v1`), so the Baseten base URL below
is used verbatim.

| Variable | Hackathon value |
| --- | --- |
| `SOVRA_AI_BASE_URL` | `https://inference.baseten.co/v1` |
| `SOVRA_AI_MODEL` | `meta-models/muse-spark-open-1026` (exact; the key works only with this model) |
| `SOVRA_AI_API_KEY` | One-time key from the Baseten invite link (single-view; copy immediately) |

Local wiring:

1. Values live in the root `.env` (gitignored, never committed;
   shape documented in `.env.example`); `compose.yaml` passes the
   four `SOVRA_AI_*` variables into both app instances with empty
   defaults, so a missing `.env` still boots keyless.
2. Paste the key into `.env`, `docker compose up -d` to recycle the
   app containers, and confirm `GET /api/plans/status` still reports
   fixture mode (`liveEnabled: false`).
3. Arm live (`SOVRA_AI_LIVE_ENABLED=true` in `.env`, recycle) only
   to run the OD-02 smoke procedure with synthetic inputs, then
   disarm and rotate/disable the key per the checklist below.

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

Every proposal and evaluation run records `sovra-planner-prompts/2`,
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
5. Disarm live mode in the persistent secret configuration, recycle affected instances and confirm sanitized fixture/unarmed status, or revoke the provider key.
   Record the sanitized run log as OD-02 evidence.
   Spend alerts are supplementary notifications, not hard caps or substitutes for disarming.

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

## Smoke evidence (2026-10-29, Baseten hackathon grant)

Reproducible via `scripts/smoke-live-planning.py` (spends credits;
exits 2 without spending when unarmed). Synthetic inputs only.

- Status reported `LIVE` / `liveEnabled` / `modelConfigured` with
  `sovra-planner-prompts/2`, `sovra-planner-tools/1`, baseline
  `sovra-baseline-planner/1`, and the five discovery tools.
- `POST /api/plans/propose` (age-over-18 intent, frozen policy
  binding) returned a `LIVE` candidate: model
  `meta-models/muse-spark-open-1026`, `CANDIDATE_ONLY`, 5 tool
  calls, ~9 s latency, ~8-11k tokens, cost `unreported`, exact
  versioned citations, no invented ids.
- Unknown outcome plus invented claim returned 400 before any
  model contact.
- `POST /api/guard/validate` on the live candidate returned
  `GUARD_ACCEPTED` under `sovra-guard/1` (the guard had earlier
  explicitly rejected a candidate that cited a credential type as
  evidence, proving the adjudication is real).
- Unreachable provider host returned explicit 503
  `planning_unavailable` with no candidate and no fixture
  fallback (manual step; key never revoked).
- Evaluator baseline arm stays green in the committed suite; the
  live agent result satisfies `requireLive` (mode `LIVE`,
  `liveAcceptance: true`).

Live findings fixed during the recorded smoke (the handoff reported 384/384 green; the current tool-bound test changes remain uncommitted at this audit): tool args accept integral numbers exactly
for the policy `version` member (models emit `"version": 1`;
`PlanningToolBoundsTests.policyVersionAcceptsIntegralNumbersExactly`);
default output budget raised 2000 -> 8000 because reasoning consumes
it (one turn measured 2119 reasoning tokens); prompt v2 pins the
evidence convention (policy documents only).

## Stage 5 live re-verification (2026-10-29, OD-02)

`scripts/smoke-live-planning.py` PASSED on its first attempt against
the armed compose stack (app-a on :8080), so no second run was
needed. Exactly one provider planning call fired this stage: the
invalid intent returned 400 before any model contact, and status and
guard checks are local. Synthetic inputs only; no key, prompt, or
proof text recorded.

- Status `LIVE` / `liveEnabled` / `modelConfigured`;
  `sovra-planner-prompts/2`, `sovra-planner-tools/1`, baseline
  `sovra-baseline-planner/1`, five discovery tools; tool-schema hash
  matched the pinned `2cb3ae5f…dbff2`.
- `POST /api/plans/propose` (age-over-18 intent, frozen policy
  binding) returned a `LIVE` candidate: model
  `meta-models/muse-spark-open-1026`, `CANDIDATE_ONLY`, 5 tool calls,
  12671 ms latency, 10853 usage tokens, cost `unreported`.
- The candidate carried mode `LIVE` with `liveAcceptance: true`,
  satisfying the `PlanningService.requireLive` /
  `PlanningEvaluator.scoreLive` gate; the committed
  `PlanningEvaluationTests.liveShapedResultsSatisfyLiveAcceptance`
  pins that positive path without any provider call (scoreLive
  validates shape only, it never contacts the model).
- `POST /api/guard/validate` returned `GUARD_ACCEPTED` under
  `sovra-guard/1` (snapshot 1).
- Planning backend suite: 33/33 green (Canary 3, Config 6,
  Evaluation 5, LiveFailure 3, Mode 4, ToolBounds 12).

## Spend visibility and cap/alert guidance

Spend visibility is console-only: the OpenAI-compatible inference
endpoint returns usage tokens but no cost field (every run records
cost `unreported`), and no provider spend API was verified from this
environment. Per-call budgets (`SOVRA_AI_MAX_TOKENS` 8000,
`SOVRA_AI_MAX_TOOL_CALLS` 8, `SOVRA_AI_TIMEOUT` 10s,
`SOVRA_AI_MAX_RETRIES` 1, `SOVRA_AI_MAX_PROMPT_CHARS` 8000) bound
each request and fail closed, but no application-level cumulative
usage ledger exists across the two app instances — per-call limits
and alerts are not a total spend cap.

Before any further live run, the owner must capture in the Baseten
console and keep out of the repo (account screens carry
identifiers; never commit them):

1. Credit/grant balance immediately before and after the run date,
   with the grant expiry date.
2. Usage attributed to `meta-models/muse-spark-open-1026` on the
   run date, reconciled against the recorded token counts above.
3. Written confirmation of no-overage / no-auto-charge behavior for
   the grant account (or the exact overage terms if any exist).
4. Any available per-key or per-account spend alert / budget
   setting, with its threshold and notification channel.

Operating rule until cumulative controls land: keep
`SOVRA_AI_LIVE_ENABLED=false` by default, arm only for a bounded
manual session with a pre-declared call/token budget, disarm (and
recycle) immediately after, and rotate or revoke the key when an
evaluation window closes. Spend alerts stay supplementary
notifications, never the cap.
