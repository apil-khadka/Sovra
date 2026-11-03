# Accredited RP onboarding (PROD-015)

Production RP credentials arrive only through reviewed
accreditation — never self-minted, never unconstrained. An
operator requests with an exact contract, a trust admin approves,
and the approval mints a bound, expiring bearer credential.
Sandbox self-service stays demo-only and refuses production.

## Contract and enforcement

A request names the organization, the exact roles (`RP_CLIENT`
with optional `TENANT_MEMBER` — operator roles are not
accreditable), at least one exact `https` origin (no wildcards, no
path), and at least one exact `https` audience. States move
forward only: `REQUESTED → APPROVED | REJECTED`, `APPROVED →
REVOKED`; revocation kills the bearer immediately.
The authenticated requester id is stored with each new request, and
that principal cannot approve or reject its own accreditation even if
it also holds `TRUST_ADMIN`.
Decision transitions lock the request row and use conditional state
updates, so concurrent decisions cannot mint an unlinked credential.

Enforcement is split honestly by what the server can prove:

- **Audiences are enforced server-side.** Consent creation
  rejects audiences outside the credential's list, and
  verification already pins each presentation to the stored
  audience — the contract holds end to end. Human callers carry
  no bearer credential, so the binding skips them; unconstrained
  legacy/sandbox accounts (`NULL` list) are unaffected.
- **Origins are a validated, recorded contract.** A self-asserted
  `Origin` header proves nothing against a token thief, so
  server-side origin checks would be theater. The accredited
  origins are the audited record the edge (WAF/CORS) enforces
  from; cryptographic origin binding (mTLS/DPoP) is the staged
  follow-up, not claimed here.

Approval mints `accredited-<org>-<rand>` with the exact roles and
lists and a bounded lifetime (default 365 days, explicit earlier
expiry allowed). The plaintext token appears exactly once, in the
approval response; reads never repeat it.

## Privileged step-up

Minting production credentials is a privileged decision, so the
interactive path (`POST /api/bff/accreditations/{id}/approve`)
requires step-up on top of the role: the session must carry a
hardware-bound method and an authentication fresher than 15
minutes. Stale or weak sessions get `step_up_required` (401 —
re-authentication fixes it) and nothing is minted. Login already
refuses weak methods for privileged groups; the endpoint check is
defense in depth, and the pattern other BFF privileged actions
follow. The machine approve endpoint exists for break-glass
automation under the same role, audited with its entry point.

## Evidence

- `AccreditationFlowTests`: audience-bound round trip,
  foreign-audience refusal, revocation kill, rejection and
  double-decision conflicts, loose-binding validation, role
  gates, unknown-id 404, self-decision refusal, and concurrent
  approval serialization.
- `BffAccreditationStepUpTests` (3 tests): fresh hardware session
  approves; aged authentication and downgraded methods get
  `step_up_required` with nothing minted.
- `CrossReplicaConsentFlowTests.accreditationDecidedAcrossReplicas`:
  request/approve/use/revoke split across replicas.
