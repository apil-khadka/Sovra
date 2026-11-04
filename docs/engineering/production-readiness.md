# Production readiness and capacity assessment

**Reviewed:** 2026-11-02; source/runtime verification refreshed 2026-11-03; video artifact note updated 2026-11-04.
**Scope:** synthetic implementation and rebuilt local containers checked on 2026-11-03.
The local evidence below does not certify hosted CI, a public deployment or production operation.
**Verdict:** a working synthetic prototype with useful security and consistency foundations; production operation and capacity for large user populations are not yet demonstrated.
This assessment updates development tasks, not deployment authorization.

## 2026-11-03 delta

The verdict is unchanged: production operation and capacity for large user populations are not demonstrated.
The registry now records 13 done, 3 in progress (PROD-001 capacity contract, PROD-014 release pipeline, PROD-016 staged measurement) and 1 pending (PROD-017 independent release); those labels record implementation scope, never release approval.
The current backend source gate passed 860 tests with zero failures, errors or skips and produced an SBOM with 336 components; the repository check passed with 790 public files.
The root app pair was rebuilt, both instances reached `READY`, and migration 39 was applied with live planning disabled and provider settings empty.
Synthetic and SD-JWT browser profiles passed 34/35 tests respectively, with five and four profile-specific skips; the SD-JWT run exercised encrypted VP, tampering, ciphertext retry, denial and authorization-code/PKCE.
The fresh dual-issuer browser verifier passed 18/18 checks, demo smoke passed 45 checks, and TypeScript and Java SDKs passed 13/13 each in sequence; see the [continuation guide](continuation-guide.md) for the full dated record.
Three findings changed state and carry dated notes below: F-01 (KMS seams now dispatch to an optional provider; no real provider qualified), F-02 (JDBC shared sessions landed with tests; deployment and recovery qualification open) and F-12 (cumulative ledger landed; it is not a billing cap).
No representative load, failover, restore, deployed TLS, external wallet, live provider or real KMS test was performed in this delta either.

## What has been done

| Area | Implemented in the inspected tree | Qualification still needed |
| --- | --- | --- |
| Application | Java 25/Spring Boot backend, React frontend packaged into the application origin, two-instance Compose harness, PostgreSQL and Flyway | Reproducible production deployment, infrastructure failure isolation and rolling upgrades |
| Authorization | Tenant-scoped JDBC, database row-level security, service-level action/object checks, separate machine and browser authentication chains | Deployed IAM/network assessment, production organization onboarding and privileged authentication |
| Identity | Keycloak OIDC login with S256 PKCE, Secure/HttpOnly session cookie, CSRF protection, membership revocation checked on requests, JDBC shared BFF sessions | Production Keycloak database/clustering, shared-session deployment/recovery qualification and operational lifecycle |
| Evidence flow | Issuance, explicit holder consent, verification, durable nonce/idempotency records, atomic decision/audit writes and denial audits | Production issuer authority, key custody, complete profile qualification and restore safety |
| Protocols | SD-JWT VC/key-binding adapters, VCI/VP/DCQL and encrypted response flows, browser demo wallet with pre-authorized and authorization-code/PKCE grants | External interoperability, production verifier keys, production status distribution and remaining profile qualification |
| Documents | Software-key envelope encryption, purpose-bound grants, purge/tombstones, isolated PNG/JPEG quarantine worker, synthetic extraction and enrollment review | Production key provider, production extraction/admission pipeline, storage growth, retention and backup lifecycle |
| Product surfaces | Issuer, holder, federation, security, developer and RP desks; Java/TypeScript SDKs; NovaBank, CornerCellar and minimal integration examples | Production onboarding, durable device custody/recovery and operational product flows |
| AI | Fixture/baseline planners, live adapter, deterministic final guard, bounded tools/tokens, provider deadline and fleet cumulative budget ledger | Verified provider terms, grant-key permissions, billing-cap controls and live evaluation |
| Operations | Semantic readiness, sanitized stage telemetry, alert APIs, non-root application image, CI builds/browser/SDK checks and dependency/SBOM scans | Durable fleet observability, paging, load qualification, backup/failover drills and artifact admission |

The existing 41-task registry records 12 `demo_implemented`, 24 `partial` and five `deferred_production` tasks.
Those labels describe implementation scope; none is a production release approval or a percentage-complete estimate.
The portal and RP dashboard already exist; their stale `not_started` entries in the Markdown index have been reconciled with the registry.
Extraction, enrollment, custody, SDKs and dashboards need promotion and qualification rather than being built again from scratch.

## Evidence checked in this assessment

| Check | Fresh result | What it establishes |
| --- | --- | --- |
| `cd backend && ./mvnw verify` using installed Temurin 25.0.2 | Passed: 860 tests, zero failures/errors/skips | Current backend builds and its automated synthetic tests pass |
| `pnpm --dir frontend run typecheck`, `run lint`, `run build` | Passed | Current frontend type checks, lints and builds |
| `pnpm --dir frontend run test:e2e` with synthetic and SD-JWT profiles | Passed: native 34/5 skipped; SD-JWT 35/4 skipped | Browser holder/RP and encrypted-wallet journeys work against the matching synthetic profile |
| `pnpm --dir demo run smoke:all` | Passed: 45 checks | Running mock RP flows work against the current local synthetic stack |
| `GET /api/health/ready` on ports 8080 and 8081 | Both returned `READY` | Both existing local containers answered their configured probes |
| `GET /api/discovery` | `synthetic`, contract `0.16.0` | Running environment is a synthetic deployment |
| Cross-instance BFF session probe (historical) | Earlier image: app A `200`, app B `401`, app A again `200`; probe session logged out | Superseded by JDBC shared-session implementation and backend cross-instance tests; no fresh container-pair probe in this refresh |
| Repository validation and whitespace checks | Passed after documentation changes | Public links/syntax/private-file boundaries and diff whitespace pass |

The historical session probe reused the repository's HTTP login helper with its synthetic member fixture, then requested `/api/bff/me` through the same cookie jar on both ports.
The current refresh rebuilt the root containers and reran both wallet profiles; its browser and SDK data remains synthetic.
No representative load, failover, restore, deployed TLS, external wallet, live provider or real KMS test was performed.
The installed JDK used for this audit is not an endorsement of its release patch level.

### 2026-11-03 verification refresh (local synthetic evidence)

The local backend `verify` gate passed 860 tests with zero failures, errors or skips; SBOM generation reported 336 components.
The focused BFF issuer-flow suite passed 8/8, including authenticated-session principal and tenant bucket consumption.
Frontend typecheck, lint and build passed, and `scripts/check_repository.py` reported 790 public files.
Both root synthetic profile runs passed: native 34 with 5 intended skips; SD-JWT VC 35 with 4 intended native-verifier skips, including the 390px wallet-layout check and encrypted response flow.
The root app pair was rebuilt and returned `READY` on both ports, with migration 39 applied; environment inspection confirmed `SOVRA_AI_LIVE_ENABLED=false` and empty AI key, URL and model.
The separate dual-issuer fixture pair was rebuilt with distinct databases and passed 18/18 browser checks, including exact consent visibility, accepted Fjord/Harbor, employment NO_PATH, cancellation and secret hygiene.
NovaBank, CornerCellar and minimal relying-party smoke passed all 45 checks; TypeScript and Java SDK suites each passed 13/13 in sequence.
The Nov 3 synthetic browser source capture was 1440×900 and 132.52 seconds; it was superseded by the [Nov 4 three-minute fixture-mode story video](../../video/deliverables/sovra-three-minute.mp4), rendered at 1920×1080 and 30 fps with separate subtitles.
Neither local recording is hosted release evidence, live-provider qualification, or production qualification.
No production KMS/HSM, provider-backed planning, external wallet conformance, deployed HTTPS, restore or load qualification was performed.
The earlier direct container-pair session probe was not repeated; cross-instance session behavior remains covered by backend tests but not a fresh root-container browser probe.

## Findings that change the development plan

### F-01: Production cryptography and profile services are incomplete

**Impact:** blocks real identity processing, signing and document protection.
**Confidence:** high, directly observed source.
[KmsSigner](../../backend/src/main/java/dev/sovra/issuance/KmsSigner.java) throws on every sign operation, and [KmsVaultKekProvider](../../backend/src/main/java/dev/sovra/vault/KmsVaultKekProvider.java) throws on wrap/unwrap.
[OpenIdKeys](../../backend/src/main/java/dev/sovra/openid/OpenIdKeys.java) is an unconditional service using a deterministic synthetic private scalar and requiring synthetic enablement flags; a production verifier-key implementation is absent.
[SyntheticStatusService](../../backend/src/main/java/dev/sovra/issuance/SyntheticStatusService.java) still provides the status path, and the quarantine entrypoint explicitly refuses non-demo mode.
[ProductionStartupValidator](../../backend/src/main/java/dev/sovra/config/ProductionStartupValidator.java) supplies useful rejection checks but does not supply these missing production services.
Implement issuer signing, vault wrapping, verifier request signing/response decryption, status and worker key-use seams with production-mode rejection of every synthetic fallback.
Do not enable synthetic flags to make a production boot succeed.
Track this under PROD-005 and PROD-015.
**2026-11-03 correction:** [KmsSigner](../../backend/src/main/java/dev/sovra/issuance/KmsSigner.java) no longer throws on every call; it dispatches to an optionally registered [KmsProvider](../../backend/src/main/java/dev/sovra/kms/KmsProvider.java) with an attested call context and fails unavailable only when no G2 provider is registered, while kms-mode boot refuses by design at the startup gate.
[KmsVaultKekProvider](../../backend/src/main/java/dev/sovra/vault/KmsVaultKekProvider.java) follows the same shape for wrap and unwrap.
[FileVerifierKeys](../../backend/src/main/java/dev/sovra/openid/FileVerifierKeys.java) adds a production-shape PEM-mounted verifier-key implementation with versioned key IDs and overlap-first rotation.
What has not changed: no real KMS, HSM or TEE provider is qualified, and no ASVS assessment or production release is approved.
The synthetic status path and the quarantine non-demo refusal remain as described above.

### F-02: Browser sessions do not survive routing between replicas

**Impact:** login failures behind an ordinary load balancer; restart/rollout loses instance-local sessions and holder unlock state.
**Confidence:** high, reproduced on the running stack.
[SecurityConfig](../../backend/src/main/java/dev/sovra/config/SecurityConfig.java) uses servlet sessions, while [HolderUnlockService](../../backend/src/main/java/dev/sovra/bff/HolderUnlockService.java) stores challenges/unlocks in them.
No shared session repository/dependency/configuration was found in the backend.
Introduce issuer-local shared server-side sessions using a supported Spring Session store, with restricted serialization and explicit expiry/revocation behavior.
JDBC can reuse existing infrastructure for an initial cohort; consider Redis only when measured session traffic justifies its additional operating burden.
Preserve single-use challenge consumption atomically across replicas, including simultaneous unlock submissions and logout/revocation races.
Sticky routing can reduce immediate disruption but does not close the availability task.
Spring documents both the default in-memory distribution problem and the shared-store approach in its [Spring Session reference](https://docs.spring.io/spring-session/reference/index.html).
Track this under PROD-003.
**2026-11-03 update:** the backend now depends on `spring-session-jdbc` for shared server-side sessions, and PROD-003 is recorded done with tests.
This documentation pass ran no fresh cross-instance session probe, so the 2026-11-02 probe result stays historical rather than re-verified.
Deployment and recovery qualification remains open, including restart/rollout behavior, the production Keycloak lifecycle and unlock-challenge races under real routing.

### F-03: Deployment and identity infrastructure remain development-shaped

**Impact:** one host/database/identity-service failure can interrupt the whole service; public exposure is not qualified.
**Confidence:** high for repository configuration; actual production infrastructure was not available.
[Compose](../../compose.yaml) puts both applications, one PostgreSQL volume and one Keycloak on one bridge network/host.
Keycloak runs `start-dev` with HTTP, development credentials and no configured production database or persisted identity-service volume.
Application and Keycloak ports are published; the public-demo overlay does not add TLS, private administration, failure domains, resource limits or backups.
Application processes also receive migration-owner credentials and run Flyway at startup.
Create a separate deployment definition with HTTPS ingress, exact origins/redirects, trusted-proxy rules, private management/data paths, rotated secrets, controlled egress, resource limits, graceful drain and a dedicated migration job.
Use production Keycloak with a durable supported database and tested identity-service recovery.
Keycloak's [production guide](https://www.keycloak.org/server/configuration-production), [database guide](https://www.keycloak.org/server/db) and [cache guide](https://www.keycloak.org/server/caching) describe the relevant production boundaries.
Track this under PROD-002, PROD-004 and PROD-013.

### F-04: Request limits do not yet provide fleet-wide overload protection

**Impact:** a hot tenant, anonymous protocol traffic or repeated expensive requests can exhaust JDBC, CPU, memory and downstream budgets.
**Confidence:** high for missing configured controls; exhaustion has not been load-reproduced.
Vault/quarantine payload, grant and decoder bounds already exist, and AI tools/tokens have per-request limits.
No per-caller/tenant rate limiter or distributed admission mechanism was found; the [SEC evidence map](sov-032-sec-evidence.md) also records this gap.
Backend [base64 decoding](../../backend/src/main/java/dev/sovra/web/Bodies.java) allocates content before service-level size checks, so enforce body/JSON/parser bounds at ingress and application entry as well.
Add per-principal and per-tenant budgets, coarse anonymous abuse limits, bounded in-flight expensive work, end-to-end deadlines and explicit `429`/`503` responses with retry guidance.
Validate streamed/chunked oversized bodies, slow clients, limiter-store outage, retry storms and one noisy tenant without bypassing consent/audit/replay checks.
Track this under PROD-006.

### F-05: Database concurrency requires measurement and admission

**Impact:** adding replicas or virtual threads can increase waiting and database connection pressure without increasing throughput.
**Confidence:** high for configuration and transaction paths; bottleneck magnitude remains unmeasured.
[Application configuration](../../backend/src/main/resources/application.yaml) caps each app pool at 10 connections with a five-second acquisition timeout.
Virtual threads are enabled, but no global in-flight database-work budget is configured.
[AuditService.recordDenial](../../backend/src/main/java/dev/sovra/audit/AuditService.java) uses `REQUIRES_NEW`; when an outer transaction already holds a connection, denial auditing may need a second one.
Spring explicitly describes the resulting [pool-exhaustion risk](https://docs.spring.io/spring-framework/reference/data-access/transaction/declarative/tx-propagation.html).
Define the total connection envelope across apps, workers, sessions, identity services, migration and maintenance, with protected operational headroom.
Bound admission before connection acquisition and test denial-heavy traffic; preserve independent durable denial evidence.
Add measured statement/lock/transaction deadlines and constrain connection occupancy while calling future remote key/status services.
Any connection proxy must be qualified against [TenantDataSource](../../backend/src/main/java/dev/sovra/tenancy/TenantDataSource.java), which uses session-level `SET app.tenant` and resets it before reuse.
Transaction pooling cannot be assumed safe for that behavior.
Track this under PROD-007.

### F-06: Several reads and caches will need work as history grows

**Impact:** dashboards and shared trust reads may compete with verification for database capacity.
**Confidence:** high for source shape; performance impact is a hypothesis pending query plans/load tests.
[RpOutcomeService](../../backend/src/main/java/dev/sovra/verification/RpOutcomeService.java) counts all matching historical decisions and orders recent results by time/id.
[TelemetryService.reasonCounts](../../backend/src/main/java/dev/sovra/ops/TelemetryService.java) groups the entire tenant audit history.
The migrations do not provide every composite index for these ordering/filter combinations, and some desks expose only the first 50/100 rows.
[CachingTrustSnapshotProvider.current](../../backend/src/main/java/dev/sovra/trust/CachingTrustSnapshotProvider.java) is synchronized while it performs database reads, including on cache hits, so requests within an instance can serialize around JDBC.
Profile with realistic retained data, add justified indexes/keyset pagination, and move operational aggregates to bounded windows or incremental summaries.
Optimize trust caching only while preserving current revocation, emergency-stop and freshness semantics.
Track this under PROD-008.

### F-07: The quarantine queue is durable but not qualified for parallel throughput

**Impact:** worker replicas may wait on the same oldest row while a scan holds its transaction/lock; poison jobs can repeatedly return to the queue after rollback.
**Confidence:** high for claim SQL; observed throughput and starvation are unmeasured.
[QuarantineWorker.claim](../../backend/src/main/java/dev/sovra/worker/QuarantineWorker.java) uses an oldest-row `UPDATE` subquery, then scans before committing the same transaction.
It does not use `SKIP LOCKED`, despite a comment in [QuarantineWorkerMain](../../backend/src/main/java/dev/sovra/worker/QuarantineWorkerMain.java) describing that behavior.
The schema lacks a queue polling index on status/time and has no explicit attempt/dead-letter lifecycle.
Design a least-privilege atomic claim/lease with fencing, hard execution deadline, bounded retries and terminal review for poison jobs.
Avoid simply widening worker database privileges to add locking.
PostgreSQL documents [`SKIP LOCKED` for queue consumers](https://www.postgresql.org/docs/17/sql-select.html); it is an option to evaluate within the authorization design.
Track this under PROD-009.

### F-08: Storage growth and retention need an operating model

**Impact:** document bytes, audit, decisions, grants and expired protocol state can enlarge WAL, indexes, backup time and restore time.
**Confidence:** high for storage layout; growth rates are unknown.
[Vault migration](../../backend/src/main/resources/db/migration/V14__vault.sql) stores ciphertext in PostgreSQL `BYTEA`, up to 16 MiB per version, and services handle full byte arrays.
Purge/tombstones already exist, but no general scheduled cleanup/archival pipeline was found for expired protocol/idempotency state or large historical tables.
Set approved per-tenant storage/ingestion quotas and retention classes, then measure actual database/WAL/backup growth.
Retain replay/idempotency evidence for the complete safety horizon; expiry alone must not permit a second acceptance.
Choose partitioning/archive and issuer-local encrypted object storage only where measured growth warrants them, preserving object/version/grant/audit integrity and orphan cleanup.
Track this under PROD-010 and PROD-013.

### F-09: Fleet observability and readiness semantics need production qualification

**Impact:** operators cannot reliably assess fleet latency/error budgets or receive durable incident notification from the current APIs alone.
**Confidence:** high, directly observed source.
[TelemetryService](../../backend/src/main/java/dev/sovra/ops/TelemetryService.java) holds the last 512 timing samples per tenant/stage in memory with a 1,024-tenant nominal bound; [AlertService](../../backend/src/main/java/dev/sovra/ops/AlertService.java) maintains per-instance observation clocks.
There is no durable fleet metrics/paging deployment in the inspected configuration.
[FlowReadinessService](../../backend/src/main/java/dev/sovra/ops/FlowReadinessService.java) runs every check on each request; public probe traffic therefore consumes database work.
[KeyAvailabilityCheck](../../backend/src/main/java/dev/sovra/ops/KeyAvailabilityCheck.java) counts registered/non-revoked key rows rather than exercising a real signing/unwrap provider.
The audit/replay [rollback probe](../../backend/src/main/java/dev/sovra/ops/RollbackProbe.java) accepts a foreign-key violation as write-path evidence and always rolls back; it cannot prove a successful durable commit or complete business-path readiness.
Add bounded fleet metrics/histograms, sanitized traces/logs, redaction checks, external paging and synthetic complete-flow canaries.
Distinguish liveness, traffic readiness, provider capability and committed-path canary results; rate-limit/cache probe results within an approved freshness bound.
Track this under PROD-011.

### F-10: A large-user claim has no supporting capacity result yet

**Impact:** neither safe replica counts nor supported user/traffic limits can currently be advertised.
**Confidence:** high within the repository/evidence inspected.
Two app processes and passing concurrency correctness tests establish useful consistency behavior, not a throughput benchmark or high availability across hosts.
There is no versioned representative load harness/result with declared hardware, arrival rate, request mix, tenant skew, dataset size and dependency latency.
Keep capacity unqualified until PROD-001 and PROD-016 produce that evidence.

### F-11: Recovery and release safety remain open

**Impact:** a stale restore can resurrect consumed authority, revoked keys, deleted bytes or obsolete approval state even if a normal restart works.
**Confidence:** high for the missing repository-owned backup/failover deployment and stated evidence gaps.
Use approved local backups plus WAL/PITR, independently recoverable keys, fenced writers and a fail-closed reopen procedure for consent/replay/trust/status authority.
PostgreSQL's [PITR documentation](https://www.postgresql.org/docs/17/continuous-archiving.html) supplies the database mechanism; application authority reconciliation still needs its own design and drills.
CI already builds/tests and produces/scans SBOMs, but production needs immutable image admission, retained provenance, secret/static scanning, compatible migrations and tested rollback.
The Dockerfile uses mutable image tags and a different Node/JDK patch baseline from local checks; qualify the actual release artifact and effective versions.
Track this under PROD-013, PROD-014 and PROD-017.

### F-12: AI and the mock RP servers need explicit exposure boundaries

**Impact:** public requests could consume shared provider/issuer budgets or mistake a synthetic RP demonstration for a customer application.
**Confidence:** high for inspected paths; no exploit or metered call was attempted.
AI has request-level bounds but no shared cumulative reservation/usage ledger; keep the public-demo live-planning disarm until PROD-012 passes.
**2026-11-03 update:** the shared ledger is now implemented in PostgreSQL with atomic reserve/settle, per-round funding, unknown-usage burn, finite caps, zero retries and lease expiry, and PROD-012 is recorded done.
The ledger is defense in depth, not a billing cap: no authenticated billing API access was verified for the grant and grant-key permissions were never tested.
Keep the public-demo live-planning disarm until the conditional live gate passes with a verified no-charge budget.
[The mock RP server](../../demo/server.mjs) deliberately holds setup/RP credentials and forwards fixture issuance/consent/verification without a visitor account/session boundary; its upstream fetches have no explicit application deadline.
Those servers are useful synthetic integration examples, not a production bank/shop or production identity frontend.
Before public synthetic hosting, restrict privileges and origins/actions, enforce quotas/deadlines and separate fixture issuance from visitor authority.
Production product work must also replace page-memory-only wallet custody with a reviewed device/recovery design and implement accredited organization/application onboarding.
Track this under PROD-002, PROD-006, PROD-012 and PROD-015.

## What “lots of users” should mean for development

Registered users, daily active users, concurrent sessions, HTTP requests per second, verification decisions per second and document megabytes per second are different capacity dimensions.
Record all of them, including tenant skew, login bursts, retained history and downstream service latency.
Do not choose hardware solely from an account count.

As one planning example, 10,000 daily active users making two journeys per day at eight application HTTP calls each generate about 1.85 requests/second averaged over a day.
An assumed 20-fold peak makes that about 37 requests/second before login, polling, assets, uploads and retries.
This is arithmetic from assumptions, not observed Sovra behavior or a supported capacity claim.

For a first synthetic staging qualification, propose the following provisional targets for approval under PROD-001:

- 100 tenants, 1,000 simultaneously logged-in sessions, and at least one million retained decision/audit rows, including a hot tenant and historical cold data.
- 100 application HTTP requests/second sustained for one hour with a declared mix of consent, verification, issuance and dashboard reads; report completed journeys/second separately.
- Core API p95 at most 500 ms and p99 at most 1.5 seconds for the approved mix, excluding human interaction, redirects, model calls and asynchronous document processing; give those paths separate objectives.
- Unexpected errors below 0.1% of valid requests offered within the approved envelope, with intentional authorization/validation denials and overload rejections reported separately.
- A twofold five-minute burst and a four-hour soak, with bounded backlog, connection waits, heap, CPU, database/WAL growth and recovery after overload.
- Stable behavior after losing one app instance, with zero duplicate acceptance, missing committed decision audits, cross-tenant results or stale-authority acceptance in the correctness corpus.
- A candidate 99.9% monthly service objective and 30-minute recovery objective, subject to an owned availability design and recovery drill; approve the data-loss objective separately by data class, never allowing a lost nonce/revocation record to silently regain authority.

These are proposed test objectives, not current guarantees, sizing commitments or an approved SLA.
The staging owner must declare hardware/resources, versions, dataset generation, caller mix, key/status latency, arrival model and exact exclusions before running them.
Use an arrival-rate generator so slow responses do not silently reduce offered load and hide saturation.
Do not load-test the current shared demo or enable paid/live providers for a benchmark.

## Recommended implementation shape

Retain the current modular Spring application and PostgreSQL consistency boundary while measuring the first workload.
Deploy multiple application replicas behind a controlled HTTPS ingress in approved issuer locations, with shared BFF sessions and separate bounded workers.
Keep replay consumption, consent state, trust/status authority and decision/audit commits on a consistency-preserving primary path.
Use replicas/caches for safe historical reads only after defining acceptable lag; never let stale authorization, revocation or consent caches create fresh acceptance.
Operate the identity service and database with tested durable recovery and an approved availability topology.
Serve cacheable static assets with content fingerprints while keeping user/API/credential content private and correctly non-cacheable.

Add an external session cache, document object store or orchestration platform only when the approved workload and operational needs justify it.
The immediate work is reliable sessions, admission, queries, recovery and measurement; splitting services or sharding the database is not a prerequisite established by this audit.
Do not provision paid capacity or change the existing synthetic-only/no-new-payment launch policy through this report.

## Execution order and completion gates

The [production work breakdown](implementation-backlog.md#production-readiness-work-breakdown) and machine-readable `production_work_items` in the [task registry](implementation-tasks.json) define PROD-001 through PROD-017 with owners, dependencies and acceptance checks.
They refine existing SOV tasks and do not replace their acceptance criteria or close their remote issues.

**2026-11-03 note:** PROD-003, PROD-006, PROD-007, PROD-008 and PROD-011 are recorded done since this ordering was written; the remaining sequence runs through PROD-001, PROD-014, PROD-016 and the PROD-017 release gate.
1. **Next development batch:** PROD-001 capacity contract, PROD-003 shared sessions, PROD-006 admission controls, PROD-007 JDBC budgets, PROD-008 query/cache profiling and PROD-011 fleet instrumentation.
   Prepare PROD-002/004 deployment and identity definitions alongside them using synthetic data.
2. **Synthetic staging qualification:** add PROD-009 workers, PROD-010 lifecycle, PROD-013 recovery and PROD-014 release pipeline, then execute PROD-016 against an isolated representative environment.
   Keep uploads/model access restricted for public synthetic publication and verify host capacity/charge prevention separately.
3. **Production identity work:** complete PROD-005 production key/services and PROD-015 protocol/custody/onboarding, under the existing issuer-location and independent architecture prerequisites.
   Production provisioning/real-data processing remains blocked until the relevant SOV-037/039 approvals exist.
4. **Production release:** PROD-017 collects independent review, finding retests, approved service/data-loss targets, operational ownership and the accountable issuer/release decision.
   Enable live AI only after the conditional PROD-012 gate; provider availability must not replace deterministic authorization.

The first demonstrable milestone is a synthetic deployment that keeps a browser logged in when routing between replicas and remains safe under bounded overload.
The next is measured service capacity and replay-safe recovery.
Production identity use requires the additional cryptographic, protocol, locality and independent release evidence.

## Inspection limits and open decisions

This was a source/configuration/CI/documentation audit with a fresh backend build, frontend checks, demo smokes and small local HTTP probes.
It was not a penetration test, full protocol conformance assessment, external infrastructure review or exhaustive line-by-line security review.
No actual production host, cloud account, real issuer configuration, provider contract, traffic forecast, operational team or cost envelope was available to verify.
The proposed capacity targets, session-store choice, availability topology, retention periods, identity locations and key-provider capability intersection still require explicit project decisions.
All findings based on unmeasured contention/growth describe risks to investigate, not reproduced throughput regressions.
