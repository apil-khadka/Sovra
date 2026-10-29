# First Java synthetic vertical slice

Current progress and the remaining public-demo work are recorded in the [2026-10-29 continuation guide](continuation-guide.md).
The dated evidence below is historical and does not establish browser/profile completion.

**Purpose:** reproduce the core identity-evidence flow on the selected Java backend with real HTTP/PostgreSQL and independent negative assertions.
**Scope:** G1 in the [business implementation plan](implementation-plan.md), consolidated by SOV-035 in the [backlog](implementation-backlog.md).
This is a build specification, not an implemented flow or permission to use real identity data.

## Prerequisites

- Approved SOV-001 proof, holder-binding, trust/status freshness and session/idempotency semantics.
- Approved SOV-002 locality/custody/root threat scope and SOV-004 provider/interface contracts for dependent behavior.
- SOV-003 pinned Java 25/Spring workspace, migrations, synthetic fixtures and two-instance HTTP/PostgreSQL harness.
- Versioned API contracts, scoped authorization, durable audit and approved trust/policy revisions.

Synthetic local provider doubles must be labelled and cannot satisfy production provider/IAM evidence.
The TypeScript prototype was removed by explicit decision; its preserved JSON fixtures are migration evidence only and do not substitute for reviewed Java behavior.

## Implementation sequence

1. Qualify the selected SD-JWT VC/OpenID adapters under SOV-036, then implement the synthetic issuer and permitted `adultOver18` claim with constrained signing and idempotency.
   The existing labelled synthetic JWS may scaffold controls but does not satisfy selected-profile acceptance.
2. Implement an RP proof request and holder page showing the exact RP, purpose, claims and expiry before explicit approval.
3. Validate proof/profile, holder, audience, consent, policy, trust/status and freshness, then atomically commit one-time challenge consumption and the immutable decision/audit relation.
4. Connect the actual Meta endpoint through bounded Spring AI tools using only approved schemas, policy excerpts and minimized synthetic context.
5. Run every proposed mapping through the independent deterministic guard and real source/citation validation before creating a holder request.
6. Add semantic flow readiness and sanitized stage timing/reason evidence, including critical dependency failures with superficially healthy HTTP probes.
7. Prove the full cross-issuer flow from a clean public checkout and retain all SRS AC-01 through AC-08 outcomes.

## Required evidence

- Valid approved evidence produces exactly one fresh acceptance across two instances with healthy dependencies.
- Tampering, wrong issuer/scope/holder/audience, expiry, revocation, replay, refused/changed consent and unknown/stale authority produce no accepted evidence.
- Process restart, concurrent submission, commit interruption and response loss cannot duplicate issuance/acceptance or turn uncertainty into success.
- Unseen/incompatible schemas, invented citations and injected metadata fail safely against a frozen deterministic baseline.
- Actual model/tool/error/timeout behavior is observed with bounded work and captured sanitized configuration/results.
- Sensitive synthetic canaries do not appear in model requests, unauthorized responses, logs, traces or metric labels.
- Startup, migrations, fixture loading, HTTP/E2E commands and actual artifact/version references reproduce without private files or production secrets.

No source database is globally reachable and no model tool can sign, approve consent, modify trust/policy or accept a proof.
A completed synthetic slice supports Java migration review; the [production validation gates](security-validation-plan.md) remain separate.
Use the [dated hackathon schedule](hackathon-milestone-plan.md) only for the synthetic milestone.

## Clean-checkout reproduction (SOV-035)

Clone the local repository to a fresh directory and reproduce the
synthetic slice without private files or production secrets (`.intel/`
is git-ignored, so the clone also proves its exclusion breaks nothing):

```sh
git clone /path/to/Sovra /tmp/sovra-clean-<rand>
cd /tmp/sovra-clean-<rand>
export JAVA_HOME=$HOME/.jdk/temurin-25/Contents/Home
(cd backend && ./mvnw verify)
pnpm --dir frontend install --frozen-lockfile && pnpm --dir frontend run build
python3 scripts/e2e-issuance.py
```

Requires Docker (Testcontainers plus Compose), JDK 25, Node.js 22 with
pnpm, and the Python `cryptography` package. The e2e script boots and
tears down its own Compose stack.

Observed result (2026-10-28, synthetic profile only):

- Backend `./mvnw verify`: 261 tests, 0 failures, 0 errors, BUILD SUCCESS.
- Frontend `pnpm run build`: clean; `pnpm run lint`: 0 warnings, 0 errors.
- `scripts/e2e-issuance.py`: PASS (issue 201, byte-identical replay,
  JWKS-verified artifact, terminal REVOKED).
- `scripts/smoke-two-instance.sh`: two instances UP plus READY with live
  authority on both (run in the source checkout).

This proof covers clean-checkout reproducibility only. Live-model
acceptance (OD-02), SOV-036 profile qualification, the SOV-041 packaged
consent-to-verification suite, and independent review remain open, and
this gate grants no real-data or production authorization.

## Architecture review follow-up

Use [SOV-004 v0.3](../architecture/decisions/SOV-004-provider-key-cache-contracts.md) for the identity/key reference and synthetic-development permission.
SOV-041 must run the actual packaged consent-to-verification HTTP/browser flow across two backend instances, not just validate a credential signature.
SOV-036 qualification precedes integration acceptance without depending on SOV-032 final whole-product assessment.
Independent SOV-037 review and SOV-039 location approval remain gates before real-data provisioning/processing.
