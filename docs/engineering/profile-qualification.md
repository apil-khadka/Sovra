# Profile qualification (PROD-015)

The selected baseline is the implemented pair: pre-authorized
issuance and authorization-code/PKCE browser flows, verified as
SD-JWT VC under the `sdjwt-vc` profile. The synthetic profile
proves flow logic; only `sdjwt-vc` decides in production (the
startup gate and the verification backstop both refuse anything
else). This page inventories what in-repo evidence already proves
and what must still come from external runs before real-data
provisioning.

## Proven in-repo

- **Parity**: `WaltIdVerificationParityTests` drives the
  `sdjwt-vc` path against real SD-JWT VC artifacts with the same
  gates as synthetic — consent approval, expiry, revocation,
  trust, binding — plus tampered-artifact, disclosure-tamper,
  stripped-disclosure, and byte-identical replay cases.
  Cross-profile artifacts are rejected both directions.
- **Freshness**: `VerificationFreshnessTests` pins stale,
  unavailable, and unknown status evidence to `UNKNOWN` with the
  evidence version recorded — stale evidence never decides.
- **Revocation currency**: status evidence carries a version that
  increments on every flip; custody revocation is synchronous at
  report time, so a stolen key loses authority in the same
  transaction.
- **Trust approval boundaries**: issuance authorizes the issuer
  against the live snapshot (`authorizeIssuer`); expired issuers
  are rejected at the guard, and enrollment re-proof fails closed
  on stale sources (`STALE_SOURCE`).
- **Holder binding**: issuance and presentation both require
  proof-of-possession over canonical messages; wrong-holder use
  fails as `HOLDER_MISMATCH`, never silently.
- **Cross-replica and restart**: `CrossReplicaConsentFlowTests`
  splits consent/verify across replicas, restarts a replica
  mid-flow, and proves peers re-validate proofs.

## Required externally

In-repo evidence cannot substitute for these; they gate
real-data provisioning under PROD-017:

1. **Wallet interop**: exercise issuance and presentation
   against at least one external wallet implementation for each
   selected flow (pre-authorized and authorization-code/PKCE),
   recording versions, transcripts, and deviations.
2. **Conformance runs**: run the applicable conformance suite
   for the selected profile against the exact deployed
   artifacts and configuration; retain the report and retest
   every finding.
3. **Production status/freshness**: re-prove the freshness
   gates against the production status provider and snapshot
   feed (latency, outage, and staleness behavior), not the
   synthetic stubs — synthetic benchmark results never
   establish real-provider behavior.
4. **Issuer/source accreditation**: each production issuer and
   extraction source completes its own approval boundary review
   before its credentials verify.

Findings from any of the four feed back into the backlog as
release blockers; conditional live-AI enablement additionally
requires the PROD-012 budget posture.
