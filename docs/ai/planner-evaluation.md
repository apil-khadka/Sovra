# Planner evaluation (corpus v2, scoped discovery)

Corpus `sovra-planning-corpus/2` scores whether a planner discovers
governed unfamiliar schemas through read-only tools — never through
prompt hints or fixture branches — and whether its candidates survive
the real deterministic guard. This document stands alone: versions,
wire shapes, scoring rules, runner usage, and the pending live
prerequisites are all stated here.

## Corpus v2 (frozen)

Location: `backend/src/test/resources/planning-corpus-v2/`
(`manifest.json` pins versions plus SHA-256 digests; changing a case
requires a new corpus version, never silent edits).

| Case | Intent (all `age_over_18`, hint `["adultOver18"]`) | Baseline | Live |
| --- | --- | --- | --- |
| `V2-KNOWN` | Unscoped, old `age-check` v1 | `CANDIDATE_ONLY` synth-1/adult-status | `CANDIDATE_ONLY` synth-1/adult-status/`adultOver18`, guard `GUARD_ACCEPTED` |
| `V2-FJORD` | Scoped issuer synth-2 + type fjord-adult/1, mapped `age-check-mapped` v1 | `MANUAL_REVIEW` (fixed mapping cannot adapt) | `CANDIDATE_ONLY` synth-2/fjord/`isAdult`, guard `GUARD_ACCEPTED` |
| `V2-HARBOR` | Scoped issuer synth-2 + type harbor-adult/1, mapped v1 | `MANUAL_REVIEW` | `CANDIDATE_ONLY` synth-2/harbor/`qualifiesAsAdult`, guard `GUARD_ACCEPTED` |
| `V2-TENURE` | Scoped issuer synth-2 + type employment-tenure/1, mapped v1 | `MANUAL_REVIEW` | Refusal: `NO_PATH` or `MANUAL_REVIEW`, null plan |
| `V2-UNKNOWN-SCOPE` | Well-formed scope to unknown issuer `retired-9`, mapped v1 | `NO_PATH` | Refusal: `NO_PATH` or `MANUAL_REVIEW`, null plan (actual proposal outcome, never 400) |

Scopes are FLAT arrays (`scopeIssuerIds`, `scopeCredentialTypes`,
`scopeJurisdictions`); there is no nested scope object and no empty
`requestedClaims`. Unknown scope values are untrusted hints resolved
against approved metadata: intent validation passes, planning narrows
to the empty set and yields `NO_PATH`.

Governing configuration (also in `manifest.json`):

- Prompts `sovra-planner-prompts/3` (no fixture names; scope echoes as data)
- Tools `sovra-planner-tools/1`, hash `2cb3ae5f…dbff2`
- Baseline `sovra-baseline-planner/1`
- Registry `sovra-synthetic-schemas/1` (semantics; guard sole authority)
- Guard `sovra-guard/2` (type-specific + semantic binding)
- Old policy `sovra-synthetic-policy/age-check` v1 unchanged
  (budget `["adultOver18"]`); mapped
  `sovra-synthetic-policy/age-check-mapped` v1
  (budget all three age spellings)

### v1 is a different experiment

`sovra-planning-corpus/1` (`planning-corpus/`) stays byte-for-byte
frozen. Its `U1` names issuer `unseen-fjord-1` with the old policy and
`requestedClaims: ["isAdult"]`; v2 `V2-FJORD` uses issuer `synth-2`
with the mapped policy, hint `["adultOver18"]`, and explicit scope.
Results are NOT interchangeable: never report a v1 pass from v2
injections or vice versa.

## Scoring rules (`PlanningEvaluator.evaluateWithLive`)

- Real guard, shared context: every candidate plan adjudicates through
  `PlanGuard.validate` with `GuardContexts.fromSnapshot` (the identical
  factory production uses), the case's RP-selected policy, the pinned
  snapshot, and the explicit evaluator clock. No weaker parallel
  authorization exists: standing/epochs, per-type binding, semantic
  binding, policy budgets, and citations all enforce exactly as served.
- Data-driven expectations: each case carries its intent, refusal-vs-
  candidate flag, and exact expected issuer/type/claims. The scorer
  never branches on `caseId`.
- Case binding: candidates must sit inside the case's discovery scope
  (shared scope-binding semantics) and match the expected
  issuer/type/claims. A guard-valid legacy plan for an unfamiliar scoped
  case scores unexpected.
- Provenance: `injected-live-shaped` (passed the shape gate),
  `injected-fixture`, `missing`, `null-injection`. Shape acceptance
  never establishes actual provider execution; only an authenticated
  server capture (see below) does. Report labels stay
  injected/replayed.
- Completeness vs correctness: `complete` requires every case to have
  a live-shaped injection (no missing/null/fixture);
  `agent.liveAcceptance` mirrors `complete`. `allExpected` requires
  every live case to match its expectation. Missing, fixture, and
  unavailable outputs (e.g. provider 503 during capture) stay missing —
  never silent success.
- Proofs: `proofExecution` stays `NOT_EXECUTED`. Guard acceptance of a
  candidate never claims a proof ran; candidates are not proofs.

Negative regressions pin: suspended/expired issuers
(`GUARD_ISSUER_EPOCH_INVALID`), fabricated citations
(`GUARD_UNKNOWN_POLICY*`), selected-policy mismatch
(`GUARD_POLICY_MISMATCH`), wrong-case legacy plans (scope/expected
binding), tenure candidates
(`GUARD_UNTRUSTED_CLAIM`/`GUARD_UNSUPPORTED_OUTCOME`), and
null/missing/fixture/unavailable handling.

No fixture-specific adapter exists: the prompt names no schemas, tools
filter generically by scope, and static/injected tests never claim live
generalization.

## Runner (`scripts/evaluate-planner-corpus2.py`)

Stdlib-only. Synthetic fixtures only; tokens arrive from the
environment by name (`--token-env`, default `SOVRA_EVAL_TOKEN`) and are
never printed; capture/replay files carry sanitized proposal/guard
fields only.

- `python3 scripts/evaluate-planner-corpus2.py score-replay --replay
  <file>`: verify manifest digests/versions, score a
  `{"results": {caseId: entry}}` replay offline. With `--base-url`,
  `CANDIDATE_ONLY` plans re-adjudicate through local
  `POST /api/guard/validate` (no model call, no spend); without it,
  guard stays `NOT_EVALUATED` and the score covers shape/scope/expected
  binding only. Default mode; never spends.
- `python3 scripts/evaluate-planner-corpus2.py capture-live --base-url
  <ONE node> --token-env <name> --out <file> --confirm-spend`:
  explicit live capture (spends credits). Verifies status versions
  against the manifest, refuses on drift or fixture mode, then drives
  the five intents in seeded order through `POST /api/plans/propose`
  on ONE central planner node, adjudicates each returned plan through
  the real guard, and retains every proposal, verdict, failure,
  refusal, latency, and usage value with immutable case/config hashes.
  Without `--confirm-spend` it exits 2 without calling the planner.

Capture notes:

- One node/ledger: target a single app instance so budget accounting
  stays on one ledger; never fan out across nodes.
- Actual plans only: the guard always receives the exact returned plan
  object; no fixed fallback, no hardcoded model outputs anywhere.
- Latency: the capture records per-case `latencyMs` plus a p50/p95
  summary explicitly labeled illustrative over n=5 — not a robust
  percentile claim.
- Cost: proposal `cost` is recorded exactly as returned
  (`null`/`unreported` when the provider omits it); never zero-filled.
  Per-proposal cost visibility is unreported from this stack today.
  Separately, the provider publishes a Management billing API (daily
  cost subtotals and usage summaries); future sanitized corroboration
  may compare run windows against those account-wide totals, but those
  totals cannot attribute exact cost to one run when other callers
  share the account. No billing integration ships here and no billing
  calls run from the scorer.

## Live prerequisites (capture PENDING)

No live capture has run for corpus v2. Before any `capture-live`:

1. Grant balance immediately before/after the run date, with expiry.
2. Usage for the exact model id on the run date, reconciled against
   recorded token counts.
3. Written no-overage / no-auto-charge terms for the grant account (or
   exact overage terms).
4. Approved data processing/retention terms for the evaluation inputs.
5. Qualified per-model limits (tokens, calls, concurrency) funded in
   the budget ledger for the window.

Until these are evidenced, live stays off (`SOVRA_AI_LIVE_ENABLED`
false, budgets zero) and all v2 scores remain injected/replayed.
