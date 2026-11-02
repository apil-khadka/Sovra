# Capacity and workload contract (PROD-001)

**Status:** proposed 2026-11-02 — pending accountable approval.
Until approved, every number below is a *proposed test objective*, not a
guarantee, sizing commitment, or SLA. No user limit is supported until
PROD-016 measures it.

This contract accepts the provisional staging objectives from the
[production assessment](production-readiness.md#what-lots-of-users-should-mean-for-development)
with the workload, targets, and data-loss objectives below. It also
records the capacity-relevant implementation decisions taken while
working the PROD backlog, so later measurements can confirm or
revisit them.

## 1. Workload dimensions

Registered users, daily active users, concurrent sessions, HTTP
requests/second, verification decisions/second, and document
megabytes/second are separate dimensions. Staging qualification
declares all of them; hardware is never sized from an account count
alone.

## 2. First staging qualification: workload

| Dimension | Proposed staging objective |
| --- | --- |
| Tenants | 100, including one hot tenant at 25% of traffic and cold historical data on the rest |
| Simultaneously logged-in BFF sessions | 1,000 shared JDBC sessions across replicas |
| Retained rows | ≥1,000,000 decision/audit rows before the run starts |
| Sustained application load | 100 HTTP req/s for 1 hour, arrival-rate driven (never a fixed client pool that hides saturation) |
| Request mix | 40% verification presentations, 25% consent request/decision, 15% issuance, 20% dashboard/reads; login bursts of 50 logins/minute overlaid |
| Burst | 2× load for 5 minutes with bounded backlog and recovery |
| Soak | 4 hours at sustained load; heap, CPU, connections, WAL, and disk bounded with no growth trend |
| Failure injection | Kill one app replica mid-run: zero duplicate acceptance, zero missing committed decision audits, zero cross-tenant results, zero stale-authority acceptance |
| Dependencies | Keycloak and PostgreSQL on staging topology; key/status provider latency injected at p95 150 ms (measured separately once PROD-005 lands) |

Excluded from the core objectives and measured separately: human
interaction time, OAuth redirects, model calls, and asynchronous
document processing.

## 3. Service targets (proposed)

| Path | p95 | p99 | Error budget |
| --- | --- | --- | --- |
| Core API mix above | ≤500 ms | ≤1.5 s | Unexpected errors <0.1% of valid in-envelope requests; authorization/validation denials and overload rejections counted separately |
| BFF login dance (server time) | ≤800 ms | ≤2 s | Same budget |
| Document upload/scan admission | ≤1 s to accept/reject | ≤3 s | Bounded queue; 429 past the queue bound, never unbounded wait |
| Trust snapshot read | ≤100 ms | ≤300 ms | Stale reads never authorize; freshness bound explicit |

Availability target (candidate, needs an owned availability design
plus a recovery drill before it becomes an SLO): 99.9% monthly,
30-minute recovery objective.

## 4. Recovery objectives by data class (proposed)

| Data class | RPO | RTO | Hard rule |
| --- | --- | --- | --- |
| Nonce/replay consumption, consent state, revocation, trust/status authority | Zero loss | 30 min | A lost record must never silently regain authority; reopen is fail-closed until reconciliation completes |
| Decision/audit evidence | Zero loss of committed rows | 30 min | Committed means durably committed, not queued |
| Sessions, rate-limit counters, telemetry | Best effort | N/A | Loss degrades to re-login / cold counters, never to false acceptance |
| Document bytes and quarantine queue | Zero loss of admitted bytes | 4 hours | Poison jobs go to terminal review, never back to the queue forever |

## 5. Recorded implementation decisions

These were chosen while implementing the PROD backlog and are
provisional until PROD-016 confirms them under load:

1. **Session store is PostgreSQL (PROD-003).** Reuses existing
   infrastructure and backups; no Redis until measured session
   traffic justifies the extra operating burden. Cost per BFF
   request: one indexed session read plus periodic last-access
   writes; watch under the login-burst mix.
2. **Challenge single-use is a SQL conditional delete (PROD-003).**
   The database arbitrates cross-replica races; no distributed lock.
3. **Rate limiting is JDBC-backed token buckets (PROD-006).**
   Fleet-wide from day one on the same consistency boundary; a
   limiter-store outage fails closed with explicit 503, never open.
4. **Denial auditing keeps independent durability (PROD-007).**
   The REQUIRES_NEW shape is retained but put under a measured
   connection budget with denial-heavy load tests.
5. **Connection envelope (PROD-007):** 10/app × N apps + worker +
   sessions + Keycloak + migration + 20% operational reserve, all
   counted against database `max_connections` with admission *before*
   borrowing. No transaction-pooling proxy: `SET app.tenant` is
   session-level and unsafe to pool that way.
6. **Synchronous trust reads keep immediate revocation checks
   (PROD-008).** Caching may only remove lock-held JDBC work, never
   the emergency-stop/freshness semantics.
7. **Quarantine claim is atomic with bounded retries and terminal
   review (PROD-009).** No worker privilege widening to get there.

## 6. Open decisions for the approver

- Approve, revise, or reject each objective in sections 2–4.
- Declare staging hardware/resources, versions, dataset generation,
  and the exact request mix before PROD-016 runs.
- Name the availability owner and the paging rotation for PROD-011.
- Approve retention periods and per-tenant storage quotas (PROD-010).
- Approve the key-provider choice that PROD-005 must integrate.

## 7. Approval

| Role | Name | Date | Decision |
| --- | --- | --- | --- |
| Product / platform | | | |
| Security / issuer authority | | | |

*Signed approval moves PROD-001 to complete and unblocks capacity
claims; code work under the other PROD items proceeds against these
proposed numbers meanwhile.*
