# Release pipeline (PROD-014)

## Flow

Tags `vX.Y.Z` only. `.github/workflows/release.yml`:

1. **Gates**: full `./mvnw verify`, frontend typecheck/lint/
   build, repository checks — the same gates as every PR, re-run
   on the tag.
2. **Secret scan**: gitleaks over history with
   [.gitleaks.toml](../../.gitleaks.toml). The allowlist holds
   exactly one pattern (credential-free JDBC fragments); every
   other finding fails the release.
3. **Build + push**: backend and Keycloak images to GHCR, tagged
   `vX.Y.Z` plus commit SHA, pushed by immutable digest.
4. **Vulnerability scan**: Trivy `CRITICAL,HIGH`, fail on any
   finding. Triage is per-release: fix, upgrade the base, or
   record a time-boxed `.trivyignore` entry with the CVE, the
   reason, and the expiry — silent ignores are not allowed.
5. **SBOM + provenance**: CycloneDX SBOM per image plus SLSA
   build provenance, attested to the registry. Digests recorded
   in `release-digests.txt`, kept 365 days as release evidence.

## Privilege separation

| Actor | Holds | Cannot |
|---|---|---|
| Release workflow (GitHub OIDC) | ephemeral registry push + attest | deploy (no host/network credentials exist in GitHub) |
| Deployer (human + host key) | production compose + env file | push images (registry is write-only from the workflow) |
| Migration job | owner DB credential, per deploy | serve traffic (exits after migrating) |
| Serving runtime | app-role DB credential | migrate, read backups, reach the internet |

## Deploy-time admission

Before `up`, verify what the pipeline produced:

```sh
gh attestation verify oci://ghcr.io/<org>/sovra-backend:<tag> --owner <org>
trivy image --severity CRITICAL,HIGH ghcr.io/<org>/sovra-backend@<digest>
```

Deploy by digest, not tag (`SOVRA_VERSION` accepts a digest):
tags move, digests do not. The rollout itself is
[production-deployment.md](./production-deployment.md) (migrate →
rolling apps → verify); canary is one replica first with a
15-minute metric hold (error rate, p99, `/ready` flaps) before
the second.

## Rollback

Rollback is a previous image against the current schema — never a
migration down. Migrations are expand-only
(`MigrationCompatibilityTests` forbids drops, renames, type
rewrites, truncates, and migrate-time deletes), so version N's
code reads version N+1's schema during the roll-forward window
and after a rollback alike. Security authority moves one way:
issuer keys, revocations, decisions, and audit rows are never
deleted or rewritten by a deploy in either direction, and the
migrate job runs only forward (`restart: no`, owner credential).
Roll back with the previous digest, re-run the deploy-time verify
(attestation + scan against the digest being restored), and
confirm `/ready` plus the metric hold before declaring the
rollback complete. A rollback that needs the old schema shape is
a failed migration review, not an operation: fix forward with a
new expand-only migration.

## API evolution rule

Request/response bodies are additive-only across releases:
never remove or rename a field, never narrow an enum, never
change a type. Rationale: rolling deploys mix N and N+1, and
deserialization fails fast on unknown properties — a removed
field breaks the old replica, an added field the old client.
Additive changes deploy any time; anything else ships as a new
endpoint with the old one deprecated, then removed two releases
later with client sign-off.

## Version reconciliation

One toolchain, pinned in three places that move together:

| Tool | Version | Pinned in |
|---|---|---|
| JDK | Temurin 25 | CI setup-java, Dockerfile stages 1–2 |
| Node | 22 | CI setup-node, Dockerfile stage 0, `frontend/.nvmrc` |
| pnpm | 9 (v9 lockfile) | CI action-setup, Dockerfile, `packageManager` |
| Maven | wrapper | `./mvnw` (same in CI and image) |
| Postgres | 17.7 | compose files, tests, backup/restore images |
| Keycloak | 26.4.0 + digest | demo compose, prod Dockerfile |

Release evidence (digests, SBOMs, scan reports) is the audit
trail; the pipeline records it, humans review it.
