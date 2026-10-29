# Implementation status and continuation guide

**Reviewed:** 2026-10-29.
**Scope:** zero-new-payment public demo with synthetic identities/documents only.
This is a source/evidence reconciliation, not an independent security assessment or authorization to publish.
Use this guide before the [business plan](implementation-plan.md) and [task backlog](implementation-backlog.md); their production requirements still apply to later real-data work.

## Current implementation

The Java backend now contains authorization/audit/trust, issuance/status, consent, durable verification, deterministic guard, bounded fixture/live planning, semantic readiness, Keycloak/BFF login, software-key vault and isolated image quarantine.
React contains demo, consent and verification views; it is not the complete issuer/holder/RP/developer dashboard product.
The implemented contract is 0.6.0 in [implemented-api.openapi.yaml](implemented-api.openapi.yaml); the other API documents contain target or historical contracts.
These implementations are synthetic/demo foundations rather than completed production tasks.

Retained local Surefire XML contains 385 tests with zero failures/errors/skips across 60 report files.
Those are existing reports, not a fresh backend run for this review; stale/orphaned report files are possible and a clean `verify` result governs the next release candidate.
Frontend build and lint were rerun successfully on 2026-10-29.
The dated [browser assessment](sov-041-holder-browser-assessment.md), [vault assessment](sov-016-vault-assessment.md), [quarantine assessment](sov-017-quarantine-assessment.md) and [authority assessment](sov-040-hardening-assessment.md) describe narrower implementation evidence and remaining gaps.
All 41 GitHub issues were observed open; task implementation progress is now recorded separately from maintainer triage and issue closure.

The current working tree also contains uncommitted live-planner/tool/prompt/config changes, `.env.example` and `scripts/smoke-live-planning.py`.
Preserve and review that work before adding unrelated implementation changes.
The [live integration record](../ai/live-integration.md) reports a successful Baseten grant smoke on 2026-10-29; this review made no live provider requests and did not inspect secret values.
Endpoint/model availability is no longer the missing OD-02 item: spend/credit enforcement, processing/retention terms and complete frozen live-evaluation evidence still need verification.
Do not ask for a provider choice or a fresh API key merely to resume local work.

## What blocks the public demo

1. The browser starts on the Vite origin while OIDC callbacks/landing target backend ports; the production-like same-origin SPA path is not packaged yet.
2. No repository-owned real-browser DOM/JS suite proves login, consent and verification; the existing Python scripts exercise HTTP, not browser behavior.
3. SD-JWT artifact handling exists, but `kb+jwt`, OpenID4VCI issuance, OpenID4VP/DCQL request/response transport and independent interoperability/conformance evidence remain open under SOV-036.
4. The local Compose stack exposes development services and known fixture credentials; it is not a reviewed public hosting configuration.
5. The UI has no upload form, but authenticated vault/quarantine APIs accept caller-supplied bytes; UI omission alone does not enforce synthetic-only public inputs.
6. No actual no-charge public host/capacity, HTTPS origin, provider hard spend enforcement or complete release-evidence pack has been established by this review.

SOV-036 and SOV-041 stay open.
An artifact-layer demonstration can be labelled accurately during development, but it does not close the selected full-profile acceptance requirements.
Production KMS/HSM, an external assessor and sovereign-region procurement are not prerequisites for the synthetic implementation steps below.

## Work in this order

### 1. Preserve the current planner work and establish an offline baseline

Review the existing dirty diff, including `PlanningProperties`, `PlanningTools`, `PlanningPrompts`, their bounds tests, Compose wiring and the new smoke script.
Ensure `.env` stays ignored and only empty credential placeholders enter `.env.example`.
Use fixture mode for ordinary development/CI; do not run the live smoke automatically or leave a public endpoint armed against unverified credit limits.
The last handoff reported live mode armed; inspect only sanitized planner status before relying on that state, and explicitly disarm the controlled deployment when live execution is not intended.
Changing a shell override once does not change the persistent secret configuration for the next Compose run.
Review and commit the implementation baseline separately from follow-up features when the existing commit/push authorization applies.

Run the offline checks below and retain the actual commands, artifact/commit, effective profile and outcomes rather than copying a historical test count.
Do not print credentials, resolve Compose configuration containing secret values into logs, or upload provider responses containing sensitive material.

### 2. Package one browser origin (SOV-006/024/027/041)

Use Spring to serve the built React assets for the demo, keeping Node/pnpm in the asset-build stage only.
Use one browser-facing origin for SPA, BFF cookies, authorization callback and logout; Keycloak remains its own explicitly trusted issuer/origin.
Keep both backend instances behind that entry point for multi-instance tests.
Choose shared/persistent session behavior or explicit affinity with tested restart/logout semantics; do not assume a cookie alone makes backend sessions portable.
Configure exact Keycloak redirect/logout URIs and HTTPS behavior for the deployment profile; keep loopback allowances confined to local development.
Implement asset/history fallback without swallowing `/api`, `/oauth2`, `/login`, error dispatch or unauthorized responses.
Update the container build context/asset packaging, Compose fixture origins and documented startup command together.

Acceptance: a fresh checkout loads the built SPA, logs in, returns to the same application origin, retains the intended BFF session and logs out without manually returning from port 8080 to 5173.

### 3. Add real-browser evidence (SOV-041, issue 45)

Add a maintained, pinned repository-owned browser automation harness and a CI job using disposable synthetic services.
Drive actual DOM/JS login, consent review, approval/refusal, verification and logout through the packaged origin.
Exercise CSRF, unauthenticated access, password-only privileged login, expired/changed consent, wrong holder/audience, tampering and replay.
Use the holder/browser proof path rather than replacing it with Python-generated proofs, direct database approval or fabricated authenticated principals.
Retain the two-instance PostgreSQL HTTP concurrency/restart suites alongside the browser suite; those tests cover different boundaries.
Record synthetic and SD-JWT artifact-profile evidence separately.
Do not close SOV-041 until the actual browser and selected-profile criteria are met, including the protocol work below.

### 4. Complete the selected protocol profile (SOV-036, issue 40)

Follow [SOV-001 v0.4](../architecture/decisions/SOV-001-proof-profile.md), especially the explicit deviations in section 11.4.
Finish strong artifact origin/digest/provenance pinning and the unexercised protocol-module dependency/support review.
Implement the frozen OpenID4VCI flow and OpenID4VP signed requests, DCQL and encrypted `direct_post.jwt` response transport using the qualified maintained library interfaces.
Replace the custom `sovra-presentation/v1` binding with the selected `kb+jwt`/`sd_hash`/audience/nonce semantics in that protocol path.
Preserve current policy, consent, trust/status freshness, atomic replay, audit, idempotency and cross-profile rejection gates through the adapters.
Use independent wallet/issuer/verifier fixtures and applicable conformance suites, including malformed disclosures, downgrade, encrypted-response and replay failures.
Re-run HTTP and real-browser evidence after integration; only then reconcile full SOV-036/041 acceptance and claims.
If a selected module cannot meet the profile, document the exact incompatibility and qualify an alternative rather than inventing protocol code or silently weakening the requirement.

### 5. Qualify the live planner within the grant (SOV-013/035, OD-02)

Retain the successful smoke as technical evidence, not proof that billing is capped or provider retention terms are approved.
Verify the actual grant expiry, hard no-overage/no-auto-charge behavior, allowed model, rate limits and relevant processing/retention terms without posting credentials or private account screenshots publicly.
Add application-level admission/rate/concurrency and cumulative usage controls across both instances; per-call token limits and spend alerts are not a total spend cap.
Default public operation to fixture/unavailable mode until the no-charge boundary is evidenced; label fixture results and never silently substitute them for a failed live request.
Run any further live evaluation only within the verified existing no-charge authorization and a bounded call/token budget.
Complete the frozen baseline-versus-live corpus, unseen/incompatible-schema and citation/injection cases with failures, versions, usage and latency retained.
Smoke success alone does not complete the full evaluation or grant permission to exceed credits.
Update OD-02 status by evidence component; no new paid account, hardware or provider subscription is authorized.

### 6. Enforce the public-demo boundary and qualify hosting (SOV-027/028/030/035)

Create a separate public-demo deployment profile instead of publishing the local Compose defaults.
Use only existing/verified no-charge capacity, an approved HTTPS origin and actual charge-prevention controls; record capacity/expiry limits and a rollback/stop procedure.
Keep database, migration runner, Keycloak administration and internal worker interfaces private, rotate deployment credentials and remove schema-owner credentials from serving containers.
Restrict demo accounts/roles, disable unrestricted enrollment and avoid real-person identity fields.
Deny arbitrary vault/quarantine ingestion on every externally reachable path, including authenticated demo callers and alternate origins; permit only server-selected synthetic fixtures where the demo needs images.
Test that valid-looking caller-uploaded image bytes are rejected by the public profile even though local synthetic API tests can use them.
Keep production issuer connectivity and production credential authority unavailable; explicitly label software fixture keys and profile limitations.
Protect actual visitor/session metadata, apply abuse/resource/egress bounds and prove no diagnostics expose secrets or source content.
Retest liveness versus semantic readiness, public origin/cookies, all reachable endpoints and image/profile admission through the actual deployment configuration.
Add provenance/SBOM/secret/dependency checks, digest-pinned release inputs and a complete sanitized evidence pack before claiming public-release readiness.
Reconcile the dated Java baseline with actual local and container JDK builds: the inspected Dockerfile still pins Temurin `25.0.4.1_1` while newer candidates appear in the baseline notes.
Verify supported patch/image availability and effective dependency/plugin versions during release qualification; do not describe a proposed version as the installed or scanned artifact.
No host has been selected or provisioned by this documentation review.

## Work after the demo foundations

SOV-018/019 implement local extraction, protected exact-byte/normalized digests, immutable revisions and reviewer/source-claim eligibility; these modules are not present yet.
Their synthetic implementation can follow the existing vault/quarantine seams without waiting for production HSM procurement, and must not turn OCR/job success into identity approval.
SOV-020 adds real holder custody/recovery behavior; current demo signing/proof helpers do not satisfy that lifecycle.
SOV-021/022 add supported SDKs, developer portal, sandbox and onboarding; frontend fetch helpers are not released SDKs.
SOV-023 through SOV-026 add role dashboards; the current demo/consent/verify pages provide only a subset of the holder experience.
Vault retirement/rewrap/purge, BFF image grants, quarantine scanning/review depth and operational worker scaling remain tracked in their assessments.
Plan broader product features after the public-demo origin/browser/protocol/admission work, retaining all existing acceptance criteria.

SOV-037/038/039, production portions of SOV-006/016/017/027/028/030/031, and full SOV-032/033/034 assurance remain gates before real identity-data use or production claims.
Independent reviewers, actual sovereign locations and production key-provider access are still unappointed/unqualified; do not fabricate those approvals or make them blockers for labelled synthetic work.

## Offline verification and evidence rules

Run from the repository root using the project's existing Java 25 setup and installed validation dependencies:

```sh
(cd backend && ./mvnw clean verify)
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend run build
pnpm --dir frontend run lint
python3 scripts/check_repository.py
git diff --check
```

The clean backend run removes ambiguity from retained report counts; it is an instruction for the next implementation baseline, not a run performed by this review.
Inspect `.env` arming flags privately and explicitly force fixture mode in controlled synthetic Compose configurations before any suite that rebuilds/restarts the stack.
Never run `docker compose config` into shared logs when secrets are populated.

Use `scripts/e2e-issuance.py`, `scripts/e2e-verification.py`, `scripts/e2e-bff-login.py`, `scripts/e2e-vault.py`, `scripts/e2e-quarantine.py` and `scripts/smoke-two-instance.sh` only with disposable synthetic data and their documented prerequisites.
Several scripts rebuild/restart services, and `e2e-verification.py` ends with `docker compose down -v`; never point them at a shared or valuable database.
Qualify an isolated Compose project plus supported container/origin overrides before running suites beside an existing demo stack; do not assume every script supports the same overrides.
Repeat verification in both artifact profiles after protocol/security changes and retain the result profile labels.
The real-browser harness exists since 2026-10-29: run `pnpm --dir frontend run test:e2e` with the compose stack up (one-time `pnpm --dir frontend exec playwright install chromium`); CI evidence comes from the `browser-e2e` job in `.github/workflows/app-checks.yml`. Scope and observed behavior are recorded in [sov-041-browser-e2e.md](sov-041-browser-e2e.md).
`scripts/smoke-live-planning.py` is an explicitly credit-consuming procedure and is excluded from the offline/default CI list.

## Instruction for the next implementation agent

Read this guide, the task's acceptance criteria and the relevant current API/decision record.
Preserve the existing dirty planner diff and do not reopen the already chosen Keycloak, synthetic-only or zero-new-payment decisions.
First establish the fixture-only baseline, then implement same-origin packaged SPA delivery and real-browser E2E; complete protocol qualification, budget enforcement and public-profile admission before publication.
Keep the registry/backlog progress, API contract, versioned proof deviations and dated assessments consistent with actual evidence.
Commit/push only the authorized reviewed changes, exclude `.intel` and secrets, and keep SOV-036/041 open until their complete criteria pass.
