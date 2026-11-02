# Production deployment (PROD-002)

Versioned definition: [compose.yaml](../../deploy/production/compose.yaml)
(standalone — the demo compose at the repo root is never used for
production). Posture is enforced twice: statically by
`ProductionComposeTests`, and at boot by
`ProductionStartupValidator` (mode, KMS, origins, management port,
external migrations) plus `SchemaValidationGuard` (schema current).

## Topology

```text
internet ──TLS──> ingress ──> sovra-front ──> app-a / app-b :8080
                                    └──────> keycloak :8443 (browsers, via ingress only)
              sovra-back (internal, no egress): apps, keycloak ──> db, keycloak-db
                                                 migrate ──> db (once per deploy)
                                                 scraper ──> apps :8091 (management, internal only)
```

- Nothing publishes a port. Ingress attaches to `sovra-front`;
  `sovra-back` is `internal: true`, so databases and the migration
  job cannot reach the internet even if asked.
- Two app replicas share PostgreSQL (sessions, rate limits,
  challenges) — either replica serves any request (PROD-003/006).
- Keycloak is single-node day one; clustering only with JGroups
  JDBC_PING and the staging exercises re-run (see the
  [Keycloak runbook](../../deploy/production/keycloak/keycloak-prod.md)).
- The quarantine worker is OMITTED until the KMS KEK lands
  (PROD-005): the worker refuses non-demo mode by design, and
  production must not open sealed bytes under a software fixture.
  Until then, image admission/scanning stays disabled in
  production (uploads that need scanning are rejected by
  configuration, loudly, not silently skipped).

## Ingress contract

- Terminate TLS (1.2+, strong ciphers) at ingress; forward to apps
  over the private front network. Only these routes exist:
  - `https://app.example.com/` → `app:8080` (SPA, BFF, machine API —
    one origin by design).
  - `https://login.example.com/` → `keycloak:8443` (login pages,
    token endpoints).
- NEVER route `/actuator/*` (management lives on :8091, internal
  only), never route `:8091`, never expose `db` / `keycloak-db`.
- Pass through `X-Request-Id` when the caller sets one (else the
  app mints it); `X-Forwarded-*` may be set or not — the app never
  derives redirects from request headers (pinned by
  `BffLoginTests.forwardedHeadersCannotHijackLoginRedirect`), so a
  spoofed host cannot hijack login.
- Timeouts: connect 5s, first byte 30s (aligns with the 25s
  statement/transaction budgets + margin), idle 60s. Retry only
  idempotent GETs, never POSTs (replay rules live server-side).
- Body ceiling at ingress: 6 MB (above the 5 MB document budget so
  the app, not the edge, writes the shaped 413).

## Egress policy

- Default deny. Day one the stack initiates NOTHING outbound:
  live AI is pinned off with empty credentials in the file, no
  webhooks exist, and OIDC discovery/JWKS run over `sovra-back`
  to the internal Keycloak.
- Enabling live AI (PROD-012) is the only approved egress change:
  allowlist the one provider host, keep the file default off, and
  budget per the AI cost controls.

## Secrets

All `${VAR:?}` (required, no defaults). Inventory:

| Secret | Holder | Rotation |
|---|---|---|
| `SOVRA_DB_ADMIN_PASSWORD` | migrate job only | Rotate in DB + vault, redeploy (job runs per deploy anyway). |
| `SOVRA_APP_DB_PASSWORD` | db init, apps | `ALTER ROLE`, update vault, rolling-restart apps. Overlap: old password valid until `ALTER` commits — restart inside the window. |
| `SOVRA_QUARANTINE_DB_PASSWORD` | db init | Same as app; no live users until the worker lands. |
| `SOVRA_KC_DB_PASSWORD` | keycloak-db, keycloak | `ALTER ROLE`, update vault, restart Keycloak (single node: window it). |
| `SOVRA_BFF_CLIENT_SECRET` | Keycloak, apps | Regenerate → vault → rolling-restart apps → revoke old last. |
| `SOVRA_KC_BOOTSTRAP_*` | first boot only | Deleted after provisioning; env unset (see runbook). |
| login-host TLS pair | `/run/sovra/tls` mount | Replace files, restart Keycloak. |
| KMS credentials | PROD-005 | Defined with the provider pick. |

Rotation cadence: DB passwords 90 days, client secret 90 days or on
personnel change, TLS per certificate lifetime, bootstrap never
(it must not exist). Every rotation is a two-phase commit: new
credential valid → consumers reloaded → old revoked. The suite
pins that no secret has a default (`ProductionComposeTests`).

## Resources and charges (no-new-payment proof)

- Limits per service are in the file (apps 2C/2G, db 2C/2G,
  keycloak 2C/2G, keycloak-db 1C/1G, migrate 1C/1G): the stack fits
  a single modest host or split VMs with 8C/8G headroom; no new
  paid service is introduced — PostgreSQL, Keycloak, and the app
  are all self-hosted, and the only metered integration (live AI)
  is pinned off with empty credentials.
- JVM heaps follow the container (`MaxRAMPercentage=75`), logs are
  capped (50m × 5), and request/body/in-flight budgets bound
  per-request allocation (PROD-006/007). Charge prevention is
  structural: there is no credential that could spend money.
- Launch policy unchanged: this file provisions no new payment
  instrument and the defaults spend nothing.

## Rollout

1. Build + push images, tag `SOVRA_VERSION` (pipeline pins digests,
   PROD-014).
2. `up -d db keycloak-db` (healthy), then `up migrate` — it must
   exit 0. Non-zero aborts the deploy; apps never start against a
   half-migrated schema (depends_on
   `service_completed_successfully` + the serve-side guard).
3. Rolling apps: `up -d app-a`, wait `/api/health/ready` 200 with
   the NEW `bootId`, then `app-b`. Migrations are expand-only
   (`MigrationCompatibilityTests`), so N+1 schema serves N code
   during the overlap.
4. Verify: `/api/health/ready` 200 on both replicas with distinct
   `instanceId`s, Prometheus scraping both `:8091`, one login per
   replica, one machine-API call per replica.
5. Rollback: re-point `SOVRA_VERSION` at the previous tag and
   repeat — expand-only migrations make rollback a binary-only
   operation (no down-migration). Data written by N+1 stays
   readable by N by construction.

## Failure domains and residency (proposed)

| Domain | Blast radius | Notes |
|---|---|---|
| App replica | 1 of 2 | Any replica serves any request; ingress drains on failed `/ready`. |
| App database | full write outage | Single primary day one; backups + PITR per PROD-013. Read replica / failover is staged work, not day one. |
| Keycloak node | new logins only | Existing sessions continue; restart recovers. |
| Keycloak database | new logins only | Same backup procedure as the app DB. |
| Single host (all) | full outage | Day-one topology is single-host-capable; multi-host spread follows the staging load verdict (PROD-016). |

Residency: all data stays on the provisioned hosts / attached
volumes in the chosen region; there is no cross-border replication
until someone configures it. Real-data provisioning remains gated
by SOV-037/039 approvals — this file provisions infrastructure,
not data.
