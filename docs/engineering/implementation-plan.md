# Business implementation plan

**Baseline:** SRS v0.5, 2026-10-27.
**Status:** planned implementation; Java migration and security assurance are pending.

Build the business application on Java 25 LTS, Spring Boot, Spring Security, Spring AI and PostgreSQL, preserving issuer authority and data locality across every operation.
Security, correctness and maintainability take priority over throughput and delivery dates.
The [SRS](../requirements/software-requirements-specification.md) defines requirements and release acceptance.
The [implementation backlog](implementation-backlog.md) defines 36 actionable tasks with acceptance criteria, owner roles, dependencies and tracker links.
The [task registry](implementation-tasks.json) provides the same task data for automation and coverage checks.

## Delivery gates

| Gate | Entry and work | Exit evidence |
| --- | --- | --- |
| G0: decisions | SOV-001, SOV-002 and SOV-004; freeze proof/holder/freshness/session semantics, locality/root boundary, custody and identity/key/cache contracts | Approved versioned decision records, explicit values and independent review of security-critical choices; unresolved real-data decisions stay blocked |
| G1: synthetic Java flow | Bootstrap SOV-003, then scoped authorization/audit/trust/issuance/consent/verification/status, bounded AI/guard, contracts and semantic health; consolidate in SOV-035 | Clean-checkout real HTTP/PostgreSQL flow across two instances, actual Meta contract/evaluation and SRS AC-01 through AC-08 with positive/negative evidence |
| G2: sensitive-data foundations | Privileged lifecycle, encrypted local vault, isolated ingestion/extraction, provenance/review, holder custody, deployment/admission and measured recovery budgets/runbooks | Extended synthetic cases prove current object/purpose authority, authenticated decryption, no OCR/ID approval shortcut, locality, revocation/cache limits and replay-safe restore |
| G3: customer release | SDKs/portal and role dashboards, complete SEC suite, deployed MC exercises and independent security/privacy review | Applicable Core/Production SRS evidence, individual ASVS applicability through Level 3, all SEC/MC evidence, retested findings and accountable release approval |

G0 decisions block dependent security behavior, while the Java synthetic build harness can begin independently.
G1 proves migration feasibility and grants no permission to collect real sensitive data.
G2 uses synthetic data to prove the proposed sensitive-data boundary; real collection/signing/decryption requires the applicable G3 review and release evidence.
Component testing is part of each task from the start; the final validation tasks integrate and independently assess that evidence.
A customer pilot is a production release for these gates when it handles real identity data.

## Initial work

1. Triage SOV-001 and approve the exact initial proof profile, trust/status freshness and session/idempotency contracts.
2. Triage SOV-002 and approve data flows, issuer/operator locations, retention/custody and the root/host threat boundary.
3. Start SOV-003 with a pinned Java build and synthetic HTTP/PostgreSQL harness while those decisions are reviewed.
4. Complete SOV-004 after the proof/locality decisions, then implement the authorization, audit and trust foundations.
5. Deliver the [first vertical slice](first-vertical-slice.md) through SOV-035 before expanding product screens and document processing.

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
SOV-036 interop evidence is therefore required, and must pass before the SOV-034 release decision.
The [synthetic hackathon schedule](hackathon-milestone-plan.md) is a dated milestone reference, separate from this business plan.
Its dates, feature cuts and demo success never waive the real-data or production gates.
