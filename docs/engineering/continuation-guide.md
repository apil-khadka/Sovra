# Implementation status and continuation guide

**Reviewed:** 2026-10-30.
**Scope:** public demo with synthetic identities/documents only and no new paid services.
Passing synthetic checks does not authorize publication, real identity-data use or production claims.
Use this guide with the [implementation plan](implementation-plan.md), [task registry](implementation-tasks.json) and dated assessments.

## Current implementation

The Java backend implements authorization, audit, governed trust, issuance/status, consent, durable verification, deterministic planning guards, fixture/live planning adapters, semantic readiness, Keycloak/BFF sessions, a software-key vault and isolated image quarantine.
The implemented API contract is [0.9.0](implemented-api.openapi.yaml).
React provides demo, consent and verification screens rather than the complete issuer/holder/RP/developer dashboard product.
The container build packages React assets into Spring, so SPA, BFF, callback and logout share one application origin.
Node/pnpm run only during asset building and development.

The repository-owned Playwright suite exercises DOM/JS login, consent and native synthetic verification against the packaged application.
The BFF does not cache API requests for replay after login; successful login returns to the SPA root without a manual navigation workaround.
See [browser evidence](sov-041-browser-e2e.md) and [packaging](sov-041-same-origin-packaging.md).

The protocol implementation includes SD-JWT artifacts and `kb+jwt`, synthetic OpenID4VCI grants, signed OpenID4VP requests, DCQL and encrypted `direct_post.jwt` responses.
Separate JOSE wallet fixtures and backend adversarial suites exercise those adapters.
External wallet/conformance evidence and the complete selected-profile browser journey remain open; see [SOV-036](sov-036-protocol-assessment.md).
The current React verifier signs the native synthetic binding, so changing `SOVRA_PROFILE` alone does not qualify the browser journey for SD-JWT.

Vault and quarantine service entry points reject caller ingestion when `SOVRA_DEMO_SYNTHETIC_ONLY=true`.
The public-demo Compose overlay forces this boundary and disables live planning on both application instances.
This overlay is a restriction layer, not a provisioned or reviewed public hosting environment.

The security remediation includes BFF/machine filter isolation, shared P-256 primitives, closed roles/statuses, independently durable denial audits, transaction-safe tenant-pin cleanup, stable human quorum identities, tenant binding, platform audit scope and durable VP replay.
Signer contexts separate validated encodable values from untrusted parsed fields.
See the dated [modularity review](modularity-bugclass-review.md) for implementation history.

Planner implementation was committed before this review; preserve any current local changes based on `git status`, not an old handoff's file list.
A successful grant smoke is technical evidence, not proof of no-overage behavior, approved retention terms or complete live evaluation.
No cumulative usage ledger currently enforces an aggregate budget across application instances.
Use the [live integration record](../ai/live-integration.md) for the remaining evidence and operating rules.

## Verification baseline

The clean 2026-10-30 Java 25 build passed 498 tests with zero failures/errors/skips, including durable-denial and nested tenant-pin regressions.
An earlier 501-test report does not match that clean baseline; do not reuse retained report totals as new evidence.
Frontend typecheck/build/lint and repository checks passed.
The expanded Playwright suite passed 13/13, including tampering, wrong-holder and signed-POST replay checks.
Subsequent change-specific results belong in their dated assessments and must state the actual command, profile and deployment scope.
No live provider call is needed for the offline checks.

Use the installed Java 25 toolchain explicitly when the system default is older:

```sh
export JAVA_HOME="$HOME/.sdkman/candidates/java/25.0.2-tem"
export PATH="$JAVA_HOME/bin:$PATH"
(cd backend && ./mvnw clean verify)
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend run typecheck
pnpm --dir frontend run build
pnpm --dir frontend run lint
python3 scripts/check_repository.py
git diff --check
```

`typecheck` uses TypeScript build mode to check all referenced application, tooling and E2E projects.
The SDKMAN path above is the observed local installation, not a declaration of the current release-qualified Java patch.
Reconcile local, CI and container patch levels during release qualification.

For the browser suite, use a disposable local synthetic stack with live planning explicitly disabled:

```sh
SOVRA_AI_LIVE_ENABLED=false SOVRA_AI_API_KEY='' SOVRA_AI_BASE_URL='' SOVRA_AI_MODEL='' docker compose up --build -d
pnpm --dir frontend exec playwright install chromium
pnpm --dir frontend run test:e2e
```

Do not print populated `.env` values or resolved Compose configuration into shared logs.
A shell override controls this invocation; it does not change the persistent configuration for future runs.
The browser setup creates synthetic machine-account and journey data in the selected database.
Use disposable data and do not run destructive HTTP harnesses against a shared or valuable database.
In particular, `scripts/e2e-verification.py` ends with `docker compose down -v`.
The HTTP suites also rebuild/restart services, so qualify isolation, ports, origins and container overrides before running beside another stack.

## Next implementation priorities

1. Preserve and review the complete working tree, including untracked Java classes and migrations.
   Keep the continuation records consistent with implemented behavior and fresh evidence.
   Exclude `.intel` and secrets before any authorized commit or push.
2. Complete SOV-036/041 selected-profile browser evidence.
   Add the holder's VCI issuance and encrypted VP journey while preserving consent, trust/status freshness, RLS, audit and durable replay.
   The native React verifier still needs the selected profile's binding and artifact-delivery path.
   Add browser-visible tampering, expiry and wrong-holder/audience failures alongside the existing HTTP concurrency/restart tests.
   Qualify external wallet/conformance compatibility and record exact library adoption or incompatibilities.
   Keep SOV-036/041 open until their complete criteria pass.
3. Qualify the actual public synthetic deployment before publication.
   Establish the approved HTTPS origin, exact OIDC redirect/logout configuration, restricted accounts, private administration, rotated credentials, resource limits, rollback and sanitized release evidence.
   Verify artifact digests/provenance and effective dependency/JDK versions for the built artifact.
   Keep production issuer authority and real identity-data ingestion unavailable.
4. Before exposing live metered planning, verify grant expiry, hard no-overage/no-auto-charge enforcement, model limits and processing/retention terms.
   Implement shared admission, concurrency and cumulative usage reservations across both instances.
   Per-request token limits and spend alerts do not constitute an aggregate cap.
   Complete the frozen baseline/live evaluation only within a verified no-charge call/token budget.
5. Build SOV-018 extraction/provenance and SOV-019 enrollment review as the next product vertical slice.
   Bind protected exact-byte/normalized digests and immutable extraction revisions to source versions, corrections and reviewer eligibility.
   Require eligible approved claims at issuance; OCR/job completion must never confer identity approval.
   Follow with holder custody/recovery, SDKs, portals and role dashboards.

Production KMS/HSM, sovereign deployment qualification and independent assessment remain real-data gates.
They do not prevent continued labelled synthetic implementation.
Do not fabricate assessor approvals, provider terms, host capacity or completed external interoperability evidence.
