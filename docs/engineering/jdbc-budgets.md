# JDBC concurrency budgets (PROD-007)

Every database connection Sovra holds is counted here. The rule is
simple: admission runs *before* borrowing, every statement carries
a deadline, and the fleet's worst case stays under the database's
`max_connections` with room for an operator to get in.

## Connection envelope

| Holder | Connections | Notes |
| --- | --- | --- |
| App instance pool (`spring.datasource.hikari.maximum-pool-size`) | 10 | Serves API traffic, BFF sessions, rate buckets, and denial audits. One pool, explicitly shared — sessions and admission do not get side pools that could starve the API. |
| App instances | × N replicas | Compose runs 2; each replica holds its own 10. |
| Quarantine worker | 2 | Single process today; PROD-009 keeps the same bound per worker with a fixed worker count. |
| Keycloak | ≤ 10 | Its own pool against the same database; sized in Keycloak config, counted here. |
| Flyway (boot/migrate) | ≤ 3 | Short-lived at startup; the separate migrate job (PROD-002/PROD-014) holds the same bound. |
| Operational reserve | ≥ 20% of `max_connections` | For `psql`, backups, and failover agents. Never allocated to pools. |

Admission math: with `max_connections = 100`, two app replicas
(20) + worker (2) + Keycloak (10) + migrate (3) = 35, leaving 65
for growth and reserve. Each added replica costs exactly 10: the
replica count is the capacity lever, and PROD-016 re-validates the
envelope under the staging workload before it grows.

## Why no transaction-pooling proxy

`SET app.tenant` is session-level: a transaction-mode pooler would
hand one backend connection to several tenants per session and
silently cross tenant boundaries. Pooling stays in-process
(Hikari), and every pooled borrow re-pins and resets the tenant
(`TenantDataSource`, proven by `TenantDataSourceTests` including
the denied-path reset).

## Deadlines

| Layer | Setting | Value | Effect |
| --- | --- | --- | --- |
| Statement | `connection-init-sql: SET statement_timeout` | 25 s | PostgreSQL cancels the runaway statement (SQLState 57014 → `QueryTimeoutException`); the pool slot is freed. |
| Socket | Hikari `socketTimeout` | 30 s | Client-side backstop if the server stops responding mid-statement. |
| Transaction | `spring.transaction.default-timeout` | 25 s | Spring rolls back transactions that outlive their deadline instead of holding slots and locks. |
| Borrow | `connection-timeout` | 5 s | A thread that cannot borrow fails fast; with admission ahead of it, this means "shed load", not "wait". |

Migrations share the statement budget: any migration whose
statements exceed 25 s must run out of band (PROD-014), never by
raising the shared deadline.

## Denial audits under contention

Refusal evidence keeps its `REQUIRES_NEW` durability (`AuditService.recordDenial`):
a denial is committed even when the caller's transaction rolls back.
The cost is one extra connection per concurrent denial, inside the
same pool of 10 — `DenialContentionTests` hammers 16 simultaneous
denials and requires every row to land. If denial-heavy load ever
starves the pool, the fix is a smaller dedicated denial pool with
its own bound, not sharing more.

## Statement cancellation, typed

Deadline expiry surfaces as Spring's `QueryTimeoutException`
(SQLState 57014), not a generic 500: controllers and the API
contract map it like any other retryable dependency failure.
`JdbcTimeoutTests` pins the mapping against a real statement
timeout.
