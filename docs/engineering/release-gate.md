# Release gate (PROD-017)

No production identity use until every gate below is signed. Each
gate names its prerequisite work, its evidence, and who signs —
the signatures are the release, not the paperwork around it.

## G0 — Independent assessment (external)

- SOV-037 independent design assessment retained; all findings
  retested against the exact deployed artifacts and configuration.
- SOV-039 locality/provider approvals retained before real-data
  provisioning.
- Applicable SEC/ASVS/MC evidence completed by the assessor.
- **Signs**: independent assessor, security owner.

## G1 — Capacity and providers

- PROD-016 staged runs executed in staging; supported envelope,
  headroom, and next bottleneck published in the [capacity
  contract](capacity-contract.md).
- Production KMS provider picked, `KmsProviderConformanceTests`
  green against it, kms-mode boot verified (PROD-005 seam).
- Production status/trust feeds re-prove the freshness gates;
  synthetic benchmark results are never cited for real-provider
  capacity.
- **Signs**: capacity committee, platform owner.

## G2 — Operations and runbooks

- On-call owners named; service and data-loss objectives
  approved; customer handling agreed.
- Incident, key-compromise, rollback, and stop runbooks
  exercised (not just read): kill-a-replica, fence-and-restore
  from [recovery drill](recovery-drill-2026-11-02.md), revoke an
  accreditation mid-flow, rotate issuer keys with overlap.
- Backups encrypted with the production KMS key; restore
  credentials separated from app identities.
- **Signs**: operations owner, on-call lead.

## G3 — Release authority

- Issuer onboarding and release authority explicitly approve
  production identity use, citing the G0–G2 evidence above.
- Conditional live-AI enablement additionally requires the
  PROD-012 budget posture: funded limits, committee sign-off,
  and the armed-but-unfunded boot refusal verified.
- The release image digest, SBOM, and provenance from the
  [release pipeline](release-pipeline.md) are the admitted
  artifacts; anything else is refused at admission.
- **Signs**: issuer authority, release authority.

## Standing rules

- Every gate re-opens on provider, profile, or topology change:
  re-qualify, don't grandfather.
- Findings from any gate feed back into the [backlog](
  implementation-backlog.md) as release blockers.
- The demo stack (`compose.yaml`) never carries real data; the
  production definitions live in `deploy/production/`.
