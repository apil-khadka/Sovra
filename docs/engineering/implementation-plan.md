# Business implementation plan

**Baseline:** SRS v0.6; implementation progress reviewed 2026-10-29.
**Status:** synthetic Java control-plane code exists; full flow, provider qualification and production assurance are pending.

Build the business application on Java 25 LTS, Spring Boot, Spring Security, Spring AI and PostgreSQL, preserving issuer authority and data locality across every operation.
Security, correctness and maintainability take priority over throughput and delivery dates.
The [SRS](../requirements/software-requirements-specification.md) defines requirements and release acceptance.
The [implementation backlog](implementation-backlog.md) defines 41 actionable tasks with acceptance criteria, owner roles, dependencies and tracker links.
The [task registry](implementation-tasks.json) provides the same task data for automation and coverage checks.

## Initial public-demo profile

The first public launch uses synthetic identities/documents only and has a zero-new-payment budget.
Use self-hosted Keycloak and existing or verified no-charge resources; the paid HSM/TEE reference is deferred and is not a demo dependency.
Disable real-ID uploads, production issuers and unrestricted account enrollment; expose bounded demo actions and protect actual visitor/authentication metadata.
Public exposure requires its own reviewed deployment configuration, rotated secrets, private administration and resource/abuse limits; local test Compose defaults are not publication approval.
Verify any model or hosting free allocation and charge prevention before use; do not represent fixtures as live AI or claim a completed live-model gate without evidence.
SOV-004, SOV-006 and SOV-035 record this profile without changing the later independent/key/locality gates for real data.

## Delivery gates

| Gate | Entry and work | Exit evidence |
| --- | --- | --- |
| G0: decisions | SOV-001, SOV-002 and SOV-004; freeze proof/holder/freshness/session semantics, locality/root boundary, custody and identity/key/cache contracts | Approved versioned decision records, explicit values and independent review of security-critical choices; unresolved real-data decisions stay blocked |
| G1: synthetic Java flow | Bootstrap SOV-003, then scoped authorization/audit/trust/issuance/consent/verification/status, bounded AI/guard, contracts and semantic health; consolidate in SOV-035 | Clean-checkout real HTTP/PostgreSQL flow across two instances, actual Meta contract/evaluation and SRS AC-01 through AC-08 with positive/negative evidence |
| G2: sensitive-data foundations | Privileged lifecycle, encrypted local vault, isolated ingestion/extraction, provenance/review, holder custody, deployment/admission and measured recovery budgets/runbooks | Extended synthetic cases prove current object/purpose authority, authenticated decryption, no OCR/ID approval shortcut, locality, revocation/cache limits and replay-safe restore |
| G3: customer release | SDKs/portal and role dashboards, complete SEC suite, deployed MC exercises and independent security/privacy review | Applicable Core/Production SRS evidence, individual ASVS applicability through Level 3, all SEC/MC evidence, retested findings and accountable release approval |

Versioned G0 contracts govern synthetic development; incomplete independent/deployment approvals do not prevent labelled local implementation.
SOV-037 and SOV-039 remain explicit gates before real-data provisioning/processing, and SOV-034 retains final release approval.
G1 proves migration feasibility and grants no permission to collect real sensitive data.
G2 uses synthetic data to prove the proposed sensitive-data boundary; real collection/signing/decryption requires the applicable G3 review and release evidence.
Component testing is part of each task from the start; the final validation tasks integrate and independently assess that evidence.
A customer pilot is a production release for these gates when it handles real identity data.

## Next implementation sequence

The [continuation guide](continuation-guide.md) is the current execution reference and supersedes earlier bootstrap-only next steps.
Keycloak/BFF, authority hardening, consent/verification, semantic readiness, SD-JWT artifact adapters, vault and quarantine already exist in synthetic scope.
Do not restart those modules or ask for the provider choice again; close their recorded gaps.

1. Preserve/review the uncommitted live-planner changes and establish a fresh fixture-only baseline without spending provider credits.
2. Package the React SPA on the Spring application origin with exact OIDC callback/logout configuration and tested multi-instance session behavior.
3. Add repository-owned real-browser login/consent/verification/logout E2E and CI alongside the existing HTTP race/restart suites.
4. Finish SOV-036 kb+jwt, VCI/VP/DCQL/encrypted transports, artifact pinning and independent interoperability/conformance; rerun SOV-041 before closing either issue.
5. Verify Baseten grant limits/retention and cumulative usage controls; finish the frozen live evaluation only within proven no-charge authorization.
6. Qualify a separate zero-charge public deployment, deny arbitrary vault/quarantine uploads through all public paths, protect administration, rotate secrets and retain public-release evidence.
7. Continue synthetic extraction/enrollment, custody, SDK/portal and role-dashboard work after these demo foundations; preserve the separate real-data release gates.

SOV-037/038/039 and production key-provider work remain unsatisfied future real-data gates, not reasons to stop the synthetic demo.
Public hosting capacity, billing limits and complete conformance must not be invented or marked approved by implementation code.

## Workstream boundaries

| Responsibility | Principal tasks | Required separation |
| --- | --- | --- |
| Authority and verification | SOV-005, SOV-007 through SOV-012 | Authorization, immutable trust/policy, constrained signing, explicit consent and durable atomic acceptance |
| Advisory intelligence | SOV-013 and SOV-014 | Read-only bounded tools and independent guard; no source PII, signing, policy approval or verification authority |
| Local identity information | SOV-016 through SOV-020 | Encrypted originals/derivatives, isolated workers, protected provenance, evidence/holder review and separate credential issuance |
| Integration and product | SOV-015 and SOV-021 through SOV-026 | Standard-described custom contracts, safe SDKs, authorized APIs and scoped issuer/holder/RP/federation dashboards |
| Platform and assurance | SOV-006 and SOV-027 through SOV-034 | Separate workload/deploy/migration/key/audit authority, artifact admission, semantic readiness, measured containment and independent assessment |

A modular Java codebase does not imply one unrestricted runtime identity.
Deployable boundaries follow issuer jurisdiction and hostile-processing/key-use authority.
Cloud provider, Kubernetes, global replication and confidential-processing mechanisms remain decisions driven by the approved threat model and evidence.
Google/Hadoop/Azure research informs patterns; it does not establish Sovra's locality, confidentiality or compliance.

## Definition of done

Every task closes with its acceptance criteria, requirement/test references, implementing artifact or decision, reproducible evidence and reviewed findings.
Tests must assert the intended security outcome independently of the implementation, including safe rejection and authority boundaries.
Run packaged HTTP/database/provider/browser tests where the risk crosses those boundaries.
Do not close a security task using documentation, a scanner report or framework defaults alone.
The release retains immutable source/build/configuration references and sanitized evidence without identity data or secrets.

The [security validation plan](security-validation-plan.md) requires SEC-01 through SEC-44 and MC-01 through MC-10 for the applicable production scope.
The [consistency contract](../architecture/consistency-and-failure-modes.md) governs restore, rollback, failover, cache and writer-fencing behavior.
Missing/stale evidence, unauthorized acceptance/disclosure, unsafe fallback, consent/trust/replay bypass and unresolved high/critical findings block release.

## Scope and schedule boundaries

SOV-001 approves the full interoperable profile from the start ([record](../architecture/decisions/SOV-001-proof-profile.md)); the narrow-attestation first step is superseded.
SOV-036 is mandatory G1 profile/library qualification before profile-dependent integration acceptance; SOV-041 tests the actual packaged verification flow.
Neither task depends on final whole-product security assessment, and both feed SOV-032/034 release evidence.
The [synthetic hackathon schedule](hackathon-milestone-plan.md) is a dated milestone reference, separate from this business plan.
Its dates, feature cuts and demo success never waive the real-data or production gates.
