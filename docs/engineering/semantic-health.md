# Semantic health, safe telemetry, and security alerts (SOV-029)

G1 operations surfaces for the synthetic flow. Everything here is sanitized:
fixed codes, fixed names, durations, and counts only — never exception text,
SQL, secrets, or identity data. Contract version 0.5.0 in
[implemented-api.openapi.yaml](implemented-api.openapi.yaml).

## Liveness vs readiness

- `GET /api/health` (public) is process liveness: the process answers HTTP.
- `GET /api/health/ready` (public) is semantic flow readiness: the
  identity-evidence flow can proceed. 200 `READY` only when every check is
  UP; otherwise 503 `NOT_READY` with the per-check report so orchestrators
  stop routing flow traffic while liveness stays green.

Seven dependency probes (`backend/.../dev/sovra/ops/`):

| Check | Tests the actual |
| --- | --- |
| `database` | Connection plus `SELECT 1` |
| `migrations` | All 16 G1 relations exist in `information_schema` |
| `trust_freshness` | Live activation row plus usable issuer validity windows |
| `authorization` | Policy-version query plus the live emergency flag (freeze is fail-closed `DEGRADED`) |
| `audit_durability` | Rollback-only `audit_event` INSERT proving the commit path |
| `replay_persistence` | Rollback-only `verification_decision` INSERT proving nonce-consumption writability |
| `key_availability` | At least one registered, unrevoked issuer signing key |

The RLS-guarded probes pin `app.tenant` to the same random UUID they
insert, so the RLS check passes and the `tenant` foreign key is what
rejects the row — proving connectivity, grants, RLS evaluation, and the
commit path without persisting anything, including on a fresh database.

## Security alerts

`GET /api/alerts` (`AUDIT_READER`, `TRUST_ADMIN`) derives alerts from the
readiness report, so unsafe stale authority (`STALE_TRUST_AUTHORITY`) and
audit-commit failure (`AUDIT_COMMIT_FAILURE`) page even while HTTP probes
succeed. Full catalog: `DATABASE_UNREACHABLE`, `SCHEMA_INCOMPLETE`,
`AUTHORIZATION_DEGRADED`, `REPLAY_STORE_DEGRADED`, `KEYS_UNAVAILABLE`
(critical/high by blast radius). `firstObservedAt` tracks continuous
observation by this instance; a restart honestly restarts the clock.

## Stage timings and reason metrics

`GET /api/telemetry/summary` (`TENANT_MEMBER`, `AUDIT_READER`,
`TRUST_ADMIN`) returns, for the caller's own tenant only:

- Per-stage aggregates (`count`, `p50Ms`, `p95Ms`, `maxMs`, outcome counts)
  for `ISSUANCE_ISSUE`, `CONSENT_CREATE`, `CONSENT_DECIDE`,
  `VERIFICATION_VERIFY`. Services record one sample per call with the
  outcome classified from the exception type (`DENIED`/`REJECTED`/`ERROR`);
  the exception itself is never retained. Storage is bounded (1024 tenants,
  last 512 durations per stage) and in-memory; the durable audit log
  remains the system of record.
- Reason counts from the durable audit log (RLS applies): counts by
  fixed action, decision, and reason code.

## Canaries

`POST /api/telemetry/canary` (same roles, no input) mints a server-side
random sentinel and drives it through four containment paths: log
sanitization plus code-only emission, error/crash mapping to fixed codes,
metric-label allowlisting (closed enums, injection-impossible), and a
deterministic fixture-model probe that must return `NO_PATH` without
repeating injected text. The response reports per-channel containment and
never echoes the sentinel. The model probe is labeled `FIXTURE` and makes
no model call.

## Frontend

The Status view renders the public readiness panel; the Demo view walks
the synthetic flow over live metadata plus labeled fixtures. The demo
accepts no file uploads anywhere (no real-ID upload path exists in the
app) and connects to no production issuer. See the
[three-minute demo storyboard](../demo/three-minute-demo.md).
