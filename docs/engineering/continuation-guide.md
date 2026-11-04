# Implementation status and continuation guide

**Runtime evidence reviewed:** 2026-11-03; video artifact notes updated 2026-11-04.
**Scope:** public demo with synthetic identities/documents only and no new paid services.
Passing synthetic checks does not authorize publication, real identity-data use or production claims.
Use this guide with the [implementation plan](implementation-plan.md), [task registry](implementation-tasks.json) and dated assessments.
The [production and capacity assessment](production-readiness.md) records the current readiness gaps and the PROD-001 through PROD-017 work breakdown (registry: 13 done, 3 in progress, 1 pending; labels record scope, not release approval).
Capacity remains unqualified; a two-instance local harness is not a supported-user or high-availability claim.
This guide records local synthetic verification performed on 2026-11-03.
Local checks do not replace hosted CI, public deployment qualification or production approval.
Do not claim all features ready or hackathon-eligible until the remaining live/provider, external interoperability and release conditions are met.

## Current implementation

The Java backend implements authorization, audit, governed trust, issuance/status, consent, durable verification, deterministic planning guards, fixture/live planning adapters, semantic readiness, Keycloak/BFF sessions, a software-key vault with retention purge, isolated image quarantine with queue/metrics, extraction/enrollment review, holder custody, sandbox onboarding, and RP outcomes/metrics.
The implemented API contract is [0.16.0](implemented-api.openapi.yaml).
React provides demo, consent, verification, wallet, issuer, holder, federation, secops, developer-portal, and RP-dashboard screens.
The container build packages React assets into Spring, so SPA, BFF, callback and logout share one application origin.
Node/pnpm run only during asset building and development.
The Public demo view foregrounds the synthetic-data boundary, live readiness checks, the active issuer snapshot and policies, and direct routes into consent, verification, integration and unfamiliar-schema walkthroughs.

Governed unfamiliar-schema discovery is implemented as one frozen versioned registry, not fixture-specific branches.
[ApprovedSchemas](../../backend/src/main/java/dev/sovra/guard/ApprovedSchemas.java) binds one wire `(vct, claim)` pair to one semantic outcome: native `adultOver18` plus `isAdult` and `qualifiesAsAdult` for age over 18, with employment tenure explicitly incompatible with `age_over_18`.
The guard requires exact type, semantic, policy and citation binding for the presented type; union membership never authorizes cross-type use.
[GuardContexts](../../backend/src/main/java/dev/sovra/guard/GuardContexts.java) builds the exact guard context the served guard adjudicates, so the evaluator, tools and any offline scorer use the same trusted inputs.
Planning corpus v2 is frozen with five cases and corpus v1 is preserved; fixture and live provenance are explicit, and no live Meta corpus-v2 evaluation has run.
See the [planner evaluation](../ai/planner-evaluation.md), the [interoperability demo](../demo/interoperability.md) and the [dual-issuer topology](../demo/dual-issuer-topology.md).

Live planning spend is now tracked by a fleet-wide cumulative budget ledger in PostgreSQL (PROD-012).
Every live call reserves requests, tokens and a concurrency slot before touching the provider, then settles with actual usage, refunds an unspent reservation, or burns the estimate on uncertain outcomes.
The ledger uses per-round prefunding, finite caps, zero retries and lease expiry; the model allowlist is empty and budgets are zero by default.
It is defense in depth under qualified model assumptions, not a financial hard cap: no authenticated billing API access was verified for the grant, so monetary spend needs separate provider-side controls.
Use the [live integration record](../ai/live-integration.md) and [fleet budgets](ai-budgets.md) for the remaining evidence and operating rules.
A successful grant smoke is technical evidence, not proof of no-overage behavior, approved retention terms or complete live evaluation.

Core consent binds issuer, credential type and claims; the demo server runs a central planner plus guard, then owner-node issue, consent and verify.
Verification commits one immutable decision with its audit row in a single transaction, replays the stored response byte-for-byte on identical retry, retries safely on uncertainty and always reads fresh configuration.
The demo server carries 56 Node tests; no fixture-model response fake is counted as live evidence.
The anti-replay contract is defined by the [demo scorecard](../demo/evaluation-and-acceptance.md) (T04/T04b): exactly one decision row per challenge, byte-identical stored response on identical resubmission, conflict without rewrite on altered content, and no `REPLAY_DETECTED` code.

The repository-owned Playwright suite exercises DOM/JS login, consent and native synthetic verification against the packaged application.
The BFF does not cache API requests for replay after login; successful login returns to the SPA root without a manual navigation workaround.
See [browser evidence](sov-041-browser-e2e.md) and [packaging](sov-041-same-origin-packaging.md).

The protocol implementation includes SD-JWT artifacts and `kb+jwt`, synthetic OpenID4VCI grants, signed OpenID4VP requests, DCQL and encrypted `direct_post.jwt` responses.
Separate JOSE wallet fixtures and backend adversarial suites exercise those adapters.
The [OpenID demo wallet](sov-041-browser-wallet.md) adds in-memory browser VCI pre-authorized and authorization-code issuance with browser-owned PKCE, explicit consent, signed-request checks, encrypted VP submission and replay.
The native verifier screen retains its synthetic binding.
Both grant paths have repository browser tests; the local SD-JWT and synthetic profile suites now pass after the wallet responsive fix (see verification baseline).
External wallet/conformance evidence, production key/status services and full qualification remain open; see [SOV-036](sov-036-protocol-assessment.md).

Vault and quarantine service entry points reject caller ingestion when `SOVRA_DEMO_SYNTHETIC_ONLY=true`.
The public-demo Compose overlay forces this boundary and disables live planning on both application instances.
This overlay is a restriction layer, not a provisioned or reviewed public hosting environment.

The security remediation includes BFF/machine filter isolation, shared P-256 primitives, closed roles/statuses, independently durable denial audits, transaction-safe tenant-pin cleanup, stable human quorum identities, tenant binding, platform audit scope and durable VP replay.
Signer contexts separate validated encodable values from untrusted parsed fields.
Accreditation decisions now serialize on the case row, use a typed state and enforce requester/decider separation, while conditional updates prevent competing approvals from minting orphan credentials.
Legal holds and their register are tenant-scoped, verifier PEM pairs are checked for P-256 and key correspondence at boot, `kid` is preferred during response decryption, and KMS wrap denials use the vault authentication failure path.
The HKDF helper has RFC 5869 bounds and test vectors, and AI budget reductions apply during the day without recording a failed first reservation.
See the dated [modularity review](modularity-bugclass-review.md) for implementation history.

The synthetic records and counts below describe local verification; inspect the pushed revision's hosted checks before relying on it as release evidence.

## Feature-level readiness (2026-11-03)

| Feature | State | Evidence or limit |
| --- | --- | --- |
| Core synthetic issuance, consent and verification (native profile) | Evidenced (synthetic) | Backend `verify` passed 860 tests; BFF issuer flow passed 8/8; synthetic browser passed 34 with 5 intended skips |
| Governed unfamiliar-schema journeys (known/Fjord/Harbor accepted, employment no-path) | Evidenced (synthetic) | Fresh dual-issuer browser verifier passed 18/18; no live Meta evaluation |
| SD-JWT VC profile and browser wallet protocol | Evidenced locally (synthetic) | Browser profile passed 35 with 4 intended native-verifier skips, including encrypted VP, tamper refusal, ciphertext retry and the 390px overflow check; external wallet/conformance and production key/status services remain open |
| TypeScript and Java SDKs | Evidenced (synthetic root) | 13/13 each, run sequentially, with trust-preservation coverage |
| BFF sessions across replicas | Implemented; deployment qualification pending | JDBC shared sessions and cross-instance backend tests (PROD-003); no fresh container-pair session probe in this pass; Keycloak and recovery qualification open |
| Fleet live-AI budget ledger | Implemented; live qualification pending | Focused plus smoke tests pass; grant-key permissions unverified; ledger is not a billing cap |
| Human passkey positive ceremony | Not evidenced | Internal flows only; no external ceremony evidence |
| External wallet and protocol conformance | Not evidenced | Repository fixtures and suites only; conformance compatibility open |
| Production custody, recovery, deployment, residency, load SLOs, security assessment | Not claimed | Green unit counts do not close these; see [production-readiness](production-readiness.md) |

## Verification baseline

### 2026-11-03 source gate (local tree)

The unfiltered backend `verify` gate passed 860 tests with zero failures, errors or skips and produced an SBOM with 336 components.
The gate includes concurrent approve/reject and BFF self-approval refusal coverage for accreditation maker/checker controls.
The BFF issuer-flow suite was then rerun with the new principal-and-tenant admission assertion and passed 8/8.
The focused budget, crypto, accreditation, legal-hold, verifier-key and KMS suites passed 50/50 before the two AI configuration regressions were corrected; the final full gate passed after those corrections.
Frontend typecheck, lint and build passed, and the repository check passed with 790 public files.
Hosted checks and release qualification remain separate from this local source evidence.

### 2026-11-03 runtime record (synthetic, live AI disarmed)

The standalone dual-issuer image was rebuilt on the stable backend with distinct databases: node A on 8280 serving `synth-1` and node B on 8281 serving `synth-2`, both READY with synthetic data and live planning off.
All 13 checks passed: known, Fjord and Harbor journeys ACCEPTED with exact plans; employment returned 200 NO_PATH with a null plan and no artifact; keys differ across nodes with store locality; own-credential checks pass while foreign credentials are refused; asymmetric cross-sign refusal holds under its exact conditions.
The shared host administrator still controls both stacks, so this claims no production sovereignty, accreditation, legal KYC, real-data handling or external wallet conformance.

The first SD-JWT browser attempt on this host used app B at `localhost:8081` and exposed that B's VCI/VP objects advertised app A's default `localhost:8080` origin.
Compose now sets the absolute OpenID issuer base URL to match each replica's published port, while keeping both origins explicit and local.
After that correction, the full SD-JWT browser profile passed 35 tests with 4 intended native-verifier skips and 0 failures; the wallet's 390px horizontal-overflow assertion passed.
The synthetic browser profile passed 34 tests with 5 intended wallet skips and 0 failures.
Frontend typecheck, lint and build passed after the responsive CSS change; the container images rebuilt with live planning disabled.

The dual-issuer Compose images were rebuilt from the current source with separate databases, both nodes reachable, and live planning disabled.
The standalone interop browser verifier passed 18/18 checks against that runtime, including ACCEPTED Fjord and Harbor journeys, the employment NO_PATH refusal, decline/cancel behavior, held-request cancellation and secret-hygiene checks.
The 132.52-second, 1440×900 captioned H.264 file generated on Nov 3 is a historical source capture, not the current product-story video.
It was superseded on Nov 4 by the [three-minute synthetic walkthrough](../../video/deliverables/sovra-three-minute.mp4), rendered at 1920×1080 and 30 fps with a separate SRT subtitle file.
The current walkthrough uses fixture planning with live AI disabled and is local working evidence, not a hosted release artifact or live Meta-planning evidence.
The full commands for reproducing browser evidence and source recording are in the [interoperability demo guide](../demo/interoperability.md).

Both SDK suites passed sequentially against the rebuilt root backend: TypeScript 13/13 then Java 13/13, with trust-preservation coverage.
The root app pair reported `READY` on both ports and applied migration 39; runtime configuration confirmed synthetic profile, live AI disabled and empty provider key, URL and model.
The refreshed Public demo screen was inspected in the integrated browser at 1280x800 and 390x844; the mobile document width remained 390px.
NovaBank, CornerCellar and the minimal relying-party sample passed all 45 `smoke:all` checks against that synthetic stack.

Earlier load and restart probes are recorded separately and stay limited: mixed HTTP 200/429 responses with the restart running BEFORE the measured run.
An HTTP 200 counter does not mean ACCEPTED, and those probes claim no failover or corruption-recovery behavior.
The root two-replica harness shares one PostgreSQL store, which differs from the two-issuer topology where each node owns a separate store.

### Historical baselines

The 2026-11-02 full backend build passed 738 tests across 127 report suites with zero failures/errors/skips; that total is historical and is superseded by the 860-test gate above.
Its frontend, browser (34 passed, 5 skipped) and demo smoke (45 checks) results are likewise historical, except where the 2026-11-03 runtime record re-confirms them.
The clean 2026-10-30 Java 25 build passed 498 tests with zero failures/errors/skips, including durable-denial and nested tenant-pin regressions.
An earlier 501-test report does not match that clean baseline; do not reuse retained report totals as new evidence.
Frontend typecheck/build/lint and repository checks passed then.
The final Playwright runs at that time passed 14 applicable cases in each of the synthetic and SD-JWT profiles, including profile-appropriate tampering and replay checks.
Each run explicitly skips the cases for the other binding path.
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
2. Preserve the requalified wallet responsive-layout fix and per-replica OpenID origins.
   Continue qualifying external wallet/conformance compatibility and record exact library adoption or incompatibilities.
   Preserve the implemented pre-authorized and authorization-code/PKCE browser wallet flows and extend profile coverage where the remaining criteria require it.
   Preserve consent, trust/status freshness, RLS, audit and durable replay through the adapters.
   Add browser-visible tampering, expiry and wrong-holder/audience failures alongside the existing HTTP concurrency/restart tests.
   Keep SOV-036/041 open until their complete criteria pass.
3. Qualify the actual public synthetic deployment before publication.
   Establish the approved HTTPS origin, exact OIDC redirect/logout configuration, restricted accounts, private administration, rotated credentials, resource limits, rollback and sanitized release evidence.
   Verify artifact digests/provenance and effective dependency/JDK versions for the built artifact.
   Keep production issuer authority and real identity-data ingestion unavailable.
4. Before exposing live metered planning, verify grant expiry, hard no-overage/no-auto-charge enforcement, model limits and processing/retention terms.
   The shared ledger now implements atomic admission, concurrency and cumulative usage reservation across instances, with per-round funding and unknown-usage burn.
   Per-request token limits and spend alerts still do not constitute an aggregate cap, and the ledger itself is not a billing cap.
   Test grant-key permissions against the provider billing API and complete the frozen baseline/live evaluation only within a verified no-charge call/token budget.
5. Promote the existing SOV-018/019 extraction/enrollment, holder custody, SDKs, portals and role dashboards toward production rather than rebuilding them.
   Follow the [production work breakdown](implementation-backlog.md#production-readiness-work-breakdown), continuing through the capacity contract, release pipeline, staged measurement and the independent release gate.
   Qualify parallel workers, storage lifecycle, recovery and release artifacts before capacity expansion.
   Complete production key/profile services, device custody/recovery, accredited organization onboarding and independent release gates before real identity use.

Production KMS/HSM, sovereign deployment qualification and independent assessment remain real-data gates.
They do not prevent continued labelled synthetic implementation.
Do not fabricate assessor approvals, provider terms, host capacity or completed external interoperability evidence.
