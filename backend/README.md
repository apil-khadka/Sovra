# Sovra backend (SOV-003 bootstrap)

Java 25 + Spring Boot service. Implemented: API-key authentication,
tenant isolation with row-level security, role/action authorization with
emergency freeze, privacy-minimized audit, a two-person versioned trust
registry, and synthetic credential issuance behind a constrained signer
(SOV-005 through SOV-009). Verification, guards, and AI planning arrive
with later backlog tasks.

## Toolchain

- JDK 25 (Eclipse Temurin 25.0.5 or newer). Check with `java -version`.
  The Maven build fails fast on older JDKs (`release version 25 not supported`).
- Maven comes from the pinned wrapper (`./mvnw`, Maven 3.9.16). No install needed.
- PostgreSQL 17 for the app and integration tests (pinned `postgres:17.7` in
  tests and Compose; any 17.x works for local runs).
- Docker (or another OCI runtime) for Testcontainers tests and `compose.yaml`.

Pinned versions: Spring Boot 4.1.2, Spring AI BOM 2.0.2 (imported for version
alignment; AI starters arrive with SOV-013), Nimbus JOSE+JWT 10.3 (JOSE
substrate for Sovra-owned code; protocol modules arrive via walt-id only
after SOV-036), CycloneDX plugin 2.9.3.
See [java-spring-baseline.md](../docs/architecture/java-spring-baseline.md).

## Commands

```sh
./mvnw verify            # full build, unit + Testcontainers integration tests, SBOM
./mvnw -DskipTests package
./mvnw spring-boot:run   # local run on :8080 (needs PostgreSQL, see below)
```

`verify` writes a CycloneDX 1.6 SBOM to
`target/classes/META-INF/sbom/application.cdx.json` (also inside the jar).

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `SOVRA_DB_URL` | `jdbc:postgresql://localhost:5432/sovra` | JDBC URL |
| `SOVRA_DB_USER` | `sovra` | DB user (production: least-privilege `sovra_app`) |
| `SOVRA_DB_PASSWORD` | `changeme` | DB password (dev default only) |
| `SOVRA_DB_ADMIN_USER` | `sovra` | Flyway migration user (schema owner) |
| `SOVRA_DB_ADMIN_PASSWORD` | `changeme` | Migration password (dev default only) |
| `SOVRA_SIGNER` | `local-dev` | `local-dev` (synthetic double) or `kms` (production, G2) |
| `SOVRA_SYNTHETIC_ISSUERS_ENABLED` | `false` | Arm the synthetic issuer (dev/test only) |
| `SOVRA_SYNTHETIC_ISSUERS_ACKNOWLEDGE_NON_PRODUCTION` | `false` | Second arming flag; both must be `true` |

The app refuses to boot the synthetic signer unless both arming flags are
set; production sets `SOVRA_SIGNER=kms` and leaves them off. Service-account
credentials are managed out of band; operator SSO/MFA arrives with SOV-006.

## Local PostgreSQL without Docker

```sh
brew install postgresql@17
pg_ctl -D /opt/homebrew/var/postgresql@17 -l /tmp/sovra-pg.log start
psql -d postgres -c "CREATE USER sovra WITH PASSWORD 'probe';"
psql -d postgres -c "CREATE DATABASE sovra OWNER sovra;"
SOVRA_DB_URL=jdbc:postgresql://localhost:5432/sovra SOVRA_DB_PASSWORD=probe ./mvnw spring-boot:run
```

If something else already holds port 5432 (for example an OrbStack forward),
move the cluster to a free port instead of fighting it:

```sh
pg_ctl -D /opt/homebrew/var/postgresql@17 -w stop
# set `port = 5434` (or another free port) in postgresql.conf, then:
pg_ctl -D /opt/homebrew/var/postgresql@17 -l /tmp/sovra-pg.log -w start
```

and point `SOVRA_DB_URL` at that port. A JDBC connection to a port that
accepts TCP but never speaks PostgreSQL hangs in authentication instead of
failing, so always verify the port answers `SELECT 1` over the same address
family first.

## Endpoints

Public federation metadata: `GET /api/health` (build identity),
`GET /api/trust/snapshots/current` (active trust snapshot),
`GET /api/issuance/jwks.json` (issuer verification keys).
Everything else needs a Bearer service-account token; see
[implemented-api.openapi.yaml](../docs/engineering/implemented-api.openapi.yaml).

`/actuator/health`, `/actuator/info`: exposed but require authentication.
All other actuator endpoints are not exposed.

## Layout

- `src/main/java/dev/sovra/`: `SovraApplication`, `config/`, `health/`,
  `auth/` (API keys), `tenancy/` (RLS pinning), `authz/` (roles, cache,
  emergency flag), `audit/`, `trust/` (registry), `issuance/` (signer,
  encoder, service), `web/` (principal, error mapping).
- `src/main/resources/db/migration/`: Flyway migrations V1 (harness probe)
  through V6 (issuance + genesis trust snapshot). V6 seeds snapshot v1
  authorizing the synthetic issuer only; production supersedes it through
  the normal two-person propose/approve/activate flow (activation only
  moves forward, so v1 can only be replaced, never edited).
- `src/test/java/dev/sovra/`: `SovraPostgresBase` (shared Testcontainers
  PostgreSQL 17.7, owner context) and `SovraAppRoleBase` (same shape, app
  booted as the least-privilege role so RLS applies end to end).
- `Dockerfile`: multi-stage Temurin 25 build, non-root runtime.

`dev.sovra` coordinates are provisional until the project domain is decided.
