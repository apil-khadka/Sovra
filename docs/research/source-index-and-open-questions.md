# Research source index, revision status and verification ledger

## Available source categories

- **Organizer primary source:** locally captured Meta Global AI Developer Hackathon Participant Guide, archived privately.
- **Internal design research:** three full-text source artifacts preserved in `.intel/sources/`.
- **Standards references:** W3C Verifiable Credentials 2.0, OpenID4VCI, OpenID4VP, OpenID Federation, SD-JWT-related specs and FATF digital-ID guidance, indexed in [standards-and-validation.md](standards-and-validation.md).
- **Architectural guidance:** Azure Mission-Critical / Well-Architected principles; use only relevant SLOs, failure-mode analysis, security and health modeling. Not an instruction to build multi-region active/active in a week.
- **Reviewed security research:** [Mission-critical and security review](security-and-mission-critical-review.md), with primary-source evidence for privilege boundaries, replay-safe recovery, key-copy/cache limits, artifact admission and semantic readiness.

## Promoted implementation baseline

The [SRS v0.5](../requirements/software-requirements-specification.md) and [ADRs 028 through 032](../architecture/architecture-decision-records.md) promote the selected research controls into explicit production requirements.
The [implementation backlog](../engineering/implementation-backlog.md) assigns dependency-ordered work and acceptance evidence.
Required SEC/MC scenarios remain unexecuted; researched provider behavior is not evidence that Sovra implements or satisfies those controls.
Proof profile, live Meta contract, locality/root visibility, provider/cache policy and other SRS decisions still require deployment-specific approval and validation.

## Source truth priority

Official current standards and organizer rules > independent verified implementation tests > current project decisions > historical generated research hypotheses > marketing claims or model speculation.

## Unverified questions requiring real evidence

- Which **exact** Meta model ID is available to the participant and supports desired function calls or structured JSON? What are the actual spend/rate limits?
- Which maintained JVM JWT/JWS, VC, and holder-proof libraries support the exact selected profile and pass interoperability and adversarial tests on the [Java/Spring baseline](../architecture/java-spring-baseline.md)?
- Which parts of OID4VP 1.0 DCQL and OID4VCI 1.0 are truly implemented instead of merely inspired by them?
- How do the issuer status endpoint, cache and verifier handle tracking/correlation and stale status?
- Are Australia/Nepal examples legal representations? Assume **no**; use fictional policies until specialist legal review.
- What actual mapping performance, citation precision and false acceptance counts arise on unseen issuer documents?

## Accuracy note

Historical documents are retained unedited even if they include contradictory protocol and scoring claims. Read the local-only `.intel/source-register.md` (ignored by Git) before porting any historical example to code. This public index intentionally avoids copying private contest message captures into the open-source submission.
