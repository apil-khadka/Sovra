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
get `AiBudgetExhaustedException`, which `ApiExceptionHandler` maps to
`429` with `Retry-After` — a capacity denial, not a server error.

## Settle, refund, burn

`LivePlanner.plan` wraps the provider call in `budgets.execute`:

1. Pre-reserve checks (configuration, prompt bound, authorized
   invocation) throw before the reserve and spend nothing.
2. The reserved `AiCall` invokes the provider inside the lease.
3. Success settles with provider-reported usage, or with the estimate
   when the provider omits usage (`usageOf` returns `-1`).
4. Any exception after the reserve burns the estimate as `UNCERTAIN`
   — timeouts, crashes, and unknown provider states never refund,
   because an uncertain call may still have been charged.

The reservation estimate is conservative by construction: the full
completion cap plus the prompt ceiling at four chars per token. The
`@Scheduled` sweeper converts leases past expiry to `UNCERTAIN` in
bounded batches (1,000 per minute), freeing concurrency slots while
keeping the tokens burned. Lease expiry defaults to 120 seconds.

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

- `AiBudgetTests` (9 tests): exact settle/refund accounting,
  uncertainty burn on failure, estimate fallback, a 16-thread race
  admitting exactly 5 of budget, concurrency cap deny-and-free, token
  budget denial, sweeper burn with slot release, loud double-settle.
- `ProductionValidatorTests.armedLiveAiRequiresFundedBudget`:
  armed-but-unfunded boot is refused at the gate.
- `PlanningConfigTests`: live planner stays inert unless fully armed.
