# Staged load procedure (PROD-016)

`load/harness.mjs` is the committed synthetic arrival-rate workload:
seeded tenant skew, a consent-to-verification flow mix plus
readiness probes, fixed offered rate with drift correction, bounded
in-flight with shed accounting, and sanitized results (latencies and
status classes only — no tokens, bodies, or tenant data).

## Local smoke (done)

```sh
node load/provision.mjs --tenants=3
node load/harness.mjs --base=http://localhost:8080 --rps=10 \
  --duration-s=60 --seed=20261102 --out=load/results/smoke-2026-11-02.json
```

Result
[`smoke-2026-11-02.json`](results/smoke-2026-11-02.json): 600
offered, 401 full flows `ACCEPTED`, zero 5xx/timeouts/shed. All 25
aborts are `:denied` — honest 429 capacity verdicts on
consent create/review/decide/verify at ~40 req/s across 3 tenants —
which is the finding, not a defect: the default admission buckets
are conservative starting points pending contract sign-off.
Latency at this load: p50 3–15 ms, p95 ≤ 23 ms, p99 ≤ 26 ms per
endpoint. Tenant skew held (211/105/85 vs 55/27/18 configured).

Local provisioning mints bearer credentials by SQL for smoke only.
Staging provisions through [accredited
onboarding](../docs/engineering/accredited-onboarding.md), never
through `provision.mjs`.

## Staged runs (staging, approved)

Each run records its result file, machine resources (captured in
the file), and the capacity-contract revision it informs:

1. **Steady-state**: 30 min at the contract's offered rate.
   Assert zero 5xx/timeouts; report p50/p95/p99 per endpoint,
   offered/completed, denial rate, and saturation headroom.
2. **Spike**: 5× offered rate for 5 min. Assert the limiter sheds
   with 429/503 (no 5xx, no shed-counter growth past the
   in-flight cap) and recovery to steady latency within 2 min
   after the spike ends.
3. **Soak**: 8 h at 1.5× steady rate. Assert no latency drift,
   no connection/pool growth, and stable purge behavior
   ([retention](../docs/engineering/retention.md)).
4. **Denial / noisy tenant**: one tenant at 10× share. Assert the
   other tenants' p95 stays within 2× their steady baseline
   (per-principal buckets isolate; shared-bucket contention is a
   finding).
5. **Dependency slowdown**: inject +500 ms P95 on the trust
   snapshot/status path. Assert verification degrades to
   `UNKNOWN` with recorded versions (never `ACCEPTED` on stale
   evidence) and JDBC deadlines bound the tail (no unbounded
   queueing).
6. **One-instance loss**: kill one app replica mid-run. Assert
   zero failed flows beyond in-flight retries, session continuity
   via the shared store, and readiness flip timing.

During every run, assert correctness, not just latency:
replay/consent/audit/tenant/freshness invariants from the
existing suites hold under load, failover, and restore. The
supported envelope, headroom, and next measured bottleneck go
into the capacity contract; synthetic results never establish
real-provider capacity (re-qualify providers separately after
PROD-005/015).
