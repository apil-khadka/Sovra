# First Java synthetic vertical slice

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

1. Implement a synthetic issuer and approved narrow claim such as `adultOver18`, constrained signing and idempotent issuance with explicit key/profile/version bindings.
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
