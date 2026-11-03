# Fleet live-AI budgets (PROD-012)

Live planning is a metered external call. Without a shared ledger,
each replica would spend against its own view of the budget and the
fleet could overspend N-fold, or one tenant could starve the rest. The
budget ledger keeps one truth in PostgreSQL: every live call reserves
requests, tokens, and a concurrency slot atomically before touching
the provider, then settles with actual usage, refunds an unspent
reservation, or burns the estimate on uncertain outcomes.

## Posture

Live AI ships disarmed twice. The compose file pins
`SOVRA_AI_LIVE_ENABLED=false` with empty credentials, and all three
budget limits default to `0` in
[`application.yaml`](../../backend/src/main/resources/application.yaml)
and
[`compose.yaml`](../../deploy/production/compose.yaml). Funding any
limit is a capacity-committee decision recorded in the
[capacity contract](capacity-contract.md). The startup gate
(`ProductionStartupValidator`) refuses production boot when live AI is
armed but any of the three limits is zero — the arming flag alone can
never enable metered calls.

## Ledger design

Migration `V35__ai_budget.sql` creates two tables:

- `ai_budget_day` — one row per UTC day, snapshotting the day's
  limits and accumulating used/reserved counters.
- `ai_call_lease` — one row per live call with lifecycle
  `HELD → SETTLED | REFUNDED | UNCERTAIN`, estimate, actual usage,
  and expiry.

`AiBudgetService.reserve` runs one transaction holding the day-row
lock (`SELECT ... FOR UPDATE`) and admits only when all three checks
hold: request count under budget, token estimate inside remaining
tokens, and held leases under the concurrency cap. Over-budget callers
get `AiBudgetExhaustedException`. On the planning path `LivePlanner`
wraps that denial in `PlanningUnavailableException`, so callers see
the standard retryable 503 `planning_unavailable` — never a silent
fallback. The `ApiExceptionHandler` 429 `ai_budget_exhausted` mapping
(with `Retry-After` to the UTC-midnight reset) fires only if the
typed exception escapes unwrapped; it is not the live-planning path
today.

## Session envelope

One `plan()` is a multi-round tool session, not one HTTP call: each
tool round is another provider request with a growing transcript, so
the ledger funds the session round by round instead of pricing one
call up front:

- Admission (`LivePlanner.plan`) refuses before any reservation —
  and any provider contact — when live is not fully armed, the model
  id is not on the `SOVRA_AI_ALLOWED_MODELS` allowlist (empty denies
  everything), `SOVRA_AI_MAX_RETRIES` is not `0`, the configured
  lease cannot cover one provider timeout plus the 30 s processing
  margin, or the first prompt already exceeds the transcript byte
  cap. Listing a model id is an operator control, not qualification
  evidence: qualification is the recorded tokenizer and
  completion-cap observation described below.
- The first round's worst case is reserved up front; a per-attempt
  guard (`BudgetGuardedChatModel`, a `ChatModel` decorator the tool
  loop cannot bypass) measures the full serialized prompt — every
  message, tool call/result, and tool definition, counting the
  JSON-escaped wire size so adversarial quotes, backslashes, and
  control bytes never outgrow the estimate — refuses over-cap
  transcripts before any bytes leave, pre-funds each further round
  through `topUp`, and heartbeats the lease so a progressing session
  never trips the sweeper.
- Rounds are finite twice over: the tool budget caps tool executions,
  and the guard additionally refuses any round past
  `maxToolCalls + 1`, so a loop the tool budget does not see (for
  example tool errors that never charge) still ends before further
  spend. Worst-case session funding is therefore finite:
  `sessionBound = (maxToolCalls + 1) × roundBound(maxTranscriptBytes,
  maxTokens, maxRetries)` — 371,520 tokens at the shipped caps
  (9 rounds × (32768 + 8000 + 512)).
- SDK retries stay invisible below the decorator (pinned by test: one
  wrapper call becomes two HTTP attempts on a retried 500), which is
  why metered runs require `maxRetries=0`. Plan-level retry stays
  available as an honest re-reserved 503.

Per-round worst case is prompt bytes at one token per byte (BPE
text tokens are at least one byte each) plus the provider-honored
`maxTokens` completion cap and a 512-token per-request overhead —
all provider-specific sizing assumptions, stated per allowlisted
model after tokenizer and completion-cap observation, never
universal. The one-token-per-byte ceiling is a text-tokenizer
property, not a law: it must be re-observed for every allowlisted
model, it says nothing about non-text modalities, and wire bytes
and tokens scale differently on supplementary Unicode (12 wire
bytes per codepoint with the pinned escaping, while the token count
is whatever the model's tokenizer reports). The pinned adapter
tests prove the framework aggregates per-round usage into the final
response (150 + 250 + 360 settled as 760) and that guard estimates
meet or beat every real request body, including adversarial content
and supplementary/unpaired Unicode.

## Settle, refund, burn

`LivePlanner.plan` wraps the provider call in `budgets.execute`:

1. Pre-reserve checks (configuration, model allowlist, retries gate,
   lease adequacy, prompt/transcript bounds, authorized invocation)
   throw before the reserve and spend nothing.
2. The reserved call runs the guarded tool session inside the lease.
3. A guard refusal (over-cap transcript, round cap, mid-loop budget
   denial) settles the exact accumulated usage of the completed
   rounds — or the funded reservation when any completed round
   omitted usage — with zero further provider contact. The refusal
   propagates through the tool loop unwrapped (with a cause-chain
   backstop in both `LivePlanner` and the ledger) precisely so this
   settle path runs instead of the burn path.
4. Success settles with provider-reported aggregate usage, or with
   the live (topped-up) reservation when the provider omits usage
   (`usageOf` returns `-1`). The adapter masks omission as zero, so
   both usage readers treat a zero total as unreported: a completed
   call always spends prompt tokens, and settling an exact zero
   would refund spend the provider may still have charged.
5. Any other exception after the reserve burns the live reservation
   as `UNCERTAIN` — timeouts, crashes, and unknown provider states
   never refund, because an uncertain call may still have been
   charged server-side.

Settle records the provider-reported truth even past the funding;
that overage is logged loud as a bound violation for re-sizing
before re-arming, never hidden. The `@Scheduled` sweeper converts
leases past expiry to `UNCERTAIN` every 60 s in one transaction,
freeing concurrency slots while keeping the tokens burned. Lease
expiry defaults to 120 seconds.

## What the ledger cannot do

The ledger bounds admitted plans' provider-measured token usage to
the envelope under the stated per-model sizing assumptions, refuses
plans that do not fit the remaining funded budget, and records
honest overage when an assumption breaks. It is not a billing cap:
no authenticated billing API access was verified for this grant, so
monetary spend caps, no-overage / no-auto-charge behavior, rate and
retention terms, and tokenizer-exact prediction remain unconfirmed
for this account. A provider-side spend cap plus alerts stays a
mandatory prerequisite before any live run; see the no-charge
checklist in [live-integration.md](../../docs/ai/live-integration.md).

A deliberate design point: the service builds its own
`DataSourceTransactionManager` on its own `DataSource` instead of
accepting an injected manager, so wiring can never run reservations
outside a transaction. The race test caught exactly that failure mode
during development (6 admitted of 5) before the fix.

## Privilege and operations

The application role holds `SELECT/INSERT/UPDATE` on both tables only
— no `DELETE`, no `TRUNCATE` — so the ledger is append-and-update
under the least-privilege role. Lease rows are permanent audit
evidence of metered spend and are never purged by
[`TransientPurge`](retention.md). Day-row limits snapshot at first
creation; raising limits mid-day requires a new row or owner action,
which is intentional — limits tighten without operator surprise.

Denials surface in the standard problem body with correlation id and
instance; operators watch `ai_call_lease` for `UNCERTAIN` volume and
day rows for burn rate against the contract.

## Evidence

- `AiBudgetTests` (18 tests): exact settle/refund accounting,
  uncertainty burn on failure, estimate fallback, a 16-thread race
  admitting exactly 5 of budget, concurrency cap deny-and-free, token
  budget denial, sweeper burn with slot release, loud double-settle,
  top-up growth/denial/terminal/heartbeat plus an 8-thread top-up
  race admitting exactly the remainder, exact abort settle
  (including through a framework wrapper), live-reservation settle
  on unknown usage, and honest over-estimate settle.
- `LivePlannerBudgetTests` (13 tests, fake provider + real tools,
  prompts, and ledger): per-round funding with aggregate settle
  (6,900 tokens over 3 HTTPs) and guard estimates meeting every real
  request body; zero-spend denials for unqualified model, enabled
  SDK retries, over-cap admission, zero budget, and short lease;
  mid-loop budget abort and mid-loop transcript growth each refused
  before the next HTTP with exact completed spend settled; 500 and
  timeout burned as uncertain; missing usage settling the funded
  reservation; a runaway tool loop ended at the round cap with
  finite settle; disarmed defaults.
- `PlannerAdapterSemanticsTests` (10 tests, no database): one HTTP
  per tool round visible to an outer decorator, final usage
  aggregating every round (150 + 250 + 360 = 760), SDK retries
  invisible below the decorator, over-cap prompts aborted before
  any provider contact, JSON-escape expansion inside the estimate,
  supplementary Unicode (3000 emoji vs the real 12-byte wire form),
  unpaired surrogates, and a bounded Unicode corpus each inside the
  estimate against real provider bytes, omitted provider usage
  arriving masked as zero (settled as unknown), and the finite
  session-bound arithmetic (371,520 at shipped caps).
- `AiBudgetMappingTests`: the 429 `ai_budget_exhausted` mapping for
  unwrapped denials.
- `AiComposeMappingTests` (4 tests, no secrets): root compose
  forwards the nine AI bound variables plus arming/credential and
  budget variables to both replicas with safe defaults, `.env.example`
  documents them with deny-by-default values, and explicit values
  bind through Spring relaxed binding.
- `ProductionValidatorTests.armedLiveAiRequiresFundedBudget`:
  armed-but-unfunded boot is refused at the gate.
- `PlanningConfigTests`: live planner stays inert unless fully armed.
