# SOV-040 hardening assessment (G1 synthetic)

Date: 2026-10-28. Verdict: **implemented for the G1 synthetic
scope** with the explicit gaps below. SOV-040 stays open until its
tracker ([issue](https://github.com/apil-khadka/Sovra/issues/43))
is reviewed against this evidence.

## Criterion 1 — approval identity and quorum

Done:

- Approval identity is the authenticated account UUID recorded by
  the sealed functions; display names are labels only (two
  same-named accounts form a valid quorum; one account twice does
  not). Covered by `TrustSealTests` (10) and the rewritten
  `databaseTriggerRejectsSelfApproval`.
- Human binding columns (`*_subject`, `*_amr`) are recorded when
  present; `trust_approve` refuses same-subject quorums and sets
  `person_verified` only for two distinct bound subjects.
- Production refuses machine-only quorums with
  `ASSURANCE_INSUFFICIENT`, audited, before any business write
  (`ProductionValidatorTests`).

Open:

- BFF-session trust endpoints do not exist yet, so no caller binds
  a subject today: every current quorum records
  `person_verified=false`. Production trust changes are therefore
  fail-closed until that follow-up lands.
- Tenant-to-legal-issuer authority mapping and entitlement epochs
  need issuer/jurisdiction input (SOV-002/SOV-039); no code asserts
  legal authority.
- One person holding two IdP identities is outside Sovra's
  visibility (IdP identity-proofing, OD-10).

## Criterion 2 — sealed snapshots, restricted writers

Done (`V13__trust_seal.sql`, `TrustService` rewrite):

- `sovra_app` holds SELECT only on the six trust tables and lost
  sequence use; runtime writes go through `trust_propose`,
  `trust_approve`, `trust_activate` (SECURITY DEFINER), which
  enforce fresh versions, linked proposals, UUID-distinct
  maker/checker, and lawful activation. Direct writes are
  permission-denied (`TrustSealTests`).
- Seal triggers bind every role including the owner: no
  insert/update/delete on issuer/policy rows of an activated
  version; activation requires an approved proposal and moves
  forward only. Proven with owner-direct attempts.
- The V4 name-based self-approval trigger is replaced with a UUID
  comparison (NULL identities permitted for migration-seed rows).

## Criterion 3 — signing-boundary provenance

Done:

- Per-call re-authorization stands: exact key match, registry
  ACTIVE, active-snapshot authorization with key version, epoch,
  and status.
- Call-context check is now exact field parsing
  (`issuer`/`key`/`purpose`), not substring: embedded-issuer,
  wrong-key, missing-purpose, and malformed-segment calls refuse
  (`IssuanceNegativeTests` +4).
- Claims stay fixed to `{adultOver18: true}` in the allowlisted
  encoders; no HTTP path reaches the signer except issuance; the
  KMS stub fails loud as 503 `kms_unavailable` instead of 500.

Open:

- Approved source/claim provenance at the signing boundary needs
  enrollment and source revisions (SOV-019, G2): G1 signs the
  fixed synthetic claim set only.
- Cryptographic AAD binding arrives with the G2 vault envelope;
  at G1 the context is parsed, checked, and audit-recorded.

## Criterion 4 — production guards and adversarial tests

Done (`sovra.mode`, default `demo`):

- Startup entry scan refuses production boot with the dev signer,
  the synthetic profile, synthetic issuer/key rows, or the demo
  seed tenant — on every boot, so a restored synthetic backup is
  refused like a misconfigured fresh database
  (`ProductionBootTests`: demo boots, production refuses).
- Per-call backstops: production activation refuses synthetic
  snapshots; production approval refuses non-person-verified
  quorums; production verification rejects the synthetic profile
  (`SYNTHETIC_PROFILE_REJECTED`); production BFF forbids the demo
  http backchannel escape hatch.
- Adversarial suites: `TrustSealTests` (direct-role writes,
  fabricated approvals, late appends, backward/unapproved
  activation), production suites (10), AAD confusion (4).
  Full backend suite: 332/332 green.

## Remaining database/root powers (read before operating)

- The migration owner bypasses GRANTs by design: it can insert
  proposal/decision rows directly (still subject to the UUID
  self-approval trigger, the seal, and the lawful-activation
  trigger), delete snapshot/activation rows, and run DDL. These
  powers belong to reviewed migrations and break-glass restore,
  never to runtime code; the application identity (`sovra_app`)
  holds none of them (MC-09).
- `sovra_app` retains INSERT on business tables (credentials,
  requests, decisions, audit, memberships, service accounts):
  sealing the trust root does not seal business writes, which
  stay authorized at the service layer and tenant-isolated by
  RLS where applicable.
- Genesis (V6) is immutable seed data with NULL approval
  identity: it can only be superseded by forward activation, and
  production refuses to boot with it present.

## Related findings (not SOV-040 scope)

- Denial audits on throwing paths in non-trust services may roll
  back with the business transaction (trust methods now commit
  denials via `noRollbackFor`). SOV-007 follow-up.
- The VCT allowlist namespace stays demo-shaped
  (`https://sovra.example/vct/*`) in all modes pending issuer
  type approval (SOV-002/SOV-039).
