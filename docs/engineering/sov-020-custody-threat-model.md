# SOV-020: holder custody threat model (DR-10, demo scope)

Reviewed 2026-10-30. This is the approved demo threat model for
holder credential custody and recovery. Each scenario names its
control and the test that proves it; production-only controls
are marked open.

## Assets

- Holder private keys (device/React memory only; never server-side).
- Public holder JWKs and thumbprints (`holder_key`, tenant RLS).
- Issued credentials bound to holder thumbprints.
- Recovery cases and their replacement links.

## Scenarios

| # | Scenario | Control | Evidence |
| --- | --- | --- | --- |
| 1 | Device loss: legitimate holder loses the key | Report flips the key to COMPROMISED and revokes its credentials at once; recovery re-proofs eligibility plus a fresh-key proof under TRUST_ADMIN | HolderCustodyFlowTests lossReportRecoveryRoundTrip |
| 2 | Theft: attacker holds the device and the key | Same as loss; the stolen key's credentials are revoked at report time, before recovery completes, so presentations fail immediately | HolderCustodyFlowTests compromisedKeyLosesIssuance |
| 3 | Compromise suspected without holder cooperation | Any issuer operator may report; recovery still needs eligibility plus a fresh-key proof, so a report alone grants nothing | HolderCustodyNegativeTests reportAloneGrantsNothing |
| 4 | Attacker submits recovery for a victim case | TRUST_ADMIN role plus current enrollment eligibility plus fresh-key possession proof; missing/invalid proof terminates | HolderCustodyNegativeTests recoverNeedsFreshProof, operatorCannotRecover |
| 5 | Attacker reuses a revoked credential after recovery | Revocation is permanent; reissuance mints new credential ids through normal issuance; old ids stay REVOKED | HolderCustodyFlowTests revokedCredentialsStayRevoked |
| 6 | Attacker guesses or enumerates holder identifiers | Thumbprints are key identifiers, never identity authority; reads are tenant-scoped and role-gated; cross-tenant reads 404 | HolderCustodyNegativeTests crossTenantReadIsNotFound |
| 7 | Malicious operator approves own recovery | Recovery needs TRUST_ADMIN, distinct from the ISSUER_OPS case flow; every report/recovery decision is audit-attributed | Role matrix in AuthorizationService; audit rows per decision |
| 8 | Private key material reaches the server | SQL CHECK rejects JWKs with private fields; registration reads the case key server-side, never from caller bytes | V24 CHECK; HolderCustodyNegativeTests noPrivateMaterialStored |
| 9 | Stale eligibility authorizes recovery | Recovery re-checks live enrollment eligibility; stale or rejected cases terminate | HolderCustodyNegativeTests staleEnrollmentBlocksRecovery |
| 10 | Double recovery or replayed report | One open recovery per key (partial unique); closed cases conflict; operations are idempotent-convergent | Partial unique index; HolderCustodyNegativeTests doubleReportAndRecoverConflict |

## Open for production

Device secure-enclave custody with attestation, encrypted backup
design, MFA plus step-up reauthorization for report/recovery
(SR-02), holder-facing recovery UX with an approved
accessibility target (OD-12/UX-05), and independent review
(SOV-037).
