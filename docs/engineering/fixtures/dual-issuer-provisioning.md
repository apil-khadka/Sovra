# Dual-issuer provisioning (synthetic demo)

Reproducible two-authority setup for governed unfamiliar-schema discovery.
Trust is provisioned through the real two-person flow; signing is isolated
per node. One shared Postgres proves LOGICAL separation only (RLS + distinct
keys + per-node refusal) — never sovereign separated databases. Sovereignty
needs the two-database orchestration at the end, owned outside the backend.

## Per-node configuration

| Node | Serves | Env | Key |
| --- | --- | --- | --- |
| A | `https://sovra.example/issuers/synth-1` | `SOVRA_SYNTHETIC_ISSUERS_LOCAL_ISSUER=synth-1` (default) | P-256 scalar 1, `synth-1:v1` |
| B | `https://sovra.example/issuers/synth-2` | `SOVRA_SYNTHETIC_ISSUERS_LOCAL_ISSUER=synth-2` | P-256 scalar 3 (3G), `synth-2:v1` |

Both nodes also need the standard synthetic arming flags
(`SOVRA_SIGNER=local-dev`,
`SOVRA_SYNTHETIC_ISSUERS_ENABLED=true`,
`SOVRA_SYNTHETIC_ISSUERS_ACKNOWLEDGE_NON_PRODUCTION=true`).
Any other `LOCAL_ISSUER` value fails fast at boot.

Refusal behavior (committed regression `CrossSigningTests`): node A signs
only `synth-1:v1` refs whose AAD names synth-1 issuance, and refuses every
`synth-2` ref with `SigningRefusedException` before any crypto — even when
the active trust snapshot authorizes both issuers. Node B mirrors this.
There is no fallback and no silent re-routing.

Single-JVM harness tests that must issue for both issuers in one Spring
context use `DualIssuerTestDouble` (test sources only). It is explicitly
labelled a test double, NOT independent authority.

## Trust proposal (two-person flow)

As a `TRUST_ADMIN` maker, `POST /api/trust/proposals` (exact field names
follow `TrustService.ProposalInput`; timestamps must bracket now):

```json
{
  "note": "demo: authorize dual synthetic issuers",
  "issuers": [
    {
      "issuerId": "https://sovra.example/issuers/synth-1",
      "displayName": "Synthetic development issuer (non-production)",
      "scope": "synthetic-only",
      "credentialTypes": ["https://sovra.example/vct/adult-status/1"],
      "keyId": "synth-1",
      "keyVersion": 1,
      "publicKeyJwk": {"kty": "EC", "crv": "P-256", "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY", "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU", "kid": "synth-1"},
      "validFrom": "<now-60s>",
      "validThrough": "<now+10y>",
      "status": "ACTIVE"
    },
    {
      "issuerId": "https://sovra.example/issuers/synth-2",
      "displayName": "Synthetic second issuer (non-production)",
      "scope": "synthetic-only",
      "credentialTypes": [
        "https://sovra.example/vct/fjord-adult/1",
        "https://sovra.example/vct/harbor-adult/1",
        "https://sovra.example/vct/employment-tenure/1"
      ],
      "keyId": "synth-2",
      "keyVersion": 1,
      "publicKeyJwk": "<scalar-3 JWK: read back from GET /api/issuance/jwks.json on node B after boot, or from issuer_signing_key>",
      "validFrom": "<now-60s>",
      "validThrough": "<now+10y>",
      "status": "ACTIVE"
    }
  ],
  "policies": []
}
```

Then, as a DISTINCT `TRUST_ADMIN` checker, approve the returned proposal
id and activate the returned snapshot version. Activation only moves
forward; the genesis snapshot is superseded, never edited. Tests perform
the identical flow in `DualIssuerFixtures.ensureDualIssuers`
(idempotent: it returns early when the current snapshot already
authorizes both issuers with these type lists).

## Discovery cases on this snapshot

- Known: unscoped intent, `requestedClaims: ["adultOver18"]`, legacy
  `age-check` v1 → synth-1 adult-status candidate; guard accepts.
- Unseen compatible: `requestedClaims: ["adultOver18"]` hint + mapped
  `age-check-mapped` v1 + `scopeIssuerIds: [synth-2]` → fjord `isAdult`
  (or harbor `qualifiesAsAdult`) discovered via `getCredentialSchema`
  tool outputs; guard accepts under the mapped policy and
  `sovra-guard/2`.
- Incompatible: same hint + mapped policy +
  `scopeCredentialTypes: [employment-tenure/1]` → tools report
  `compatible: false`, proposal is `NO_PATH` with a reason (an actual
  proposal outcome, not a 400); no plan, no guard call, no consent.

New schemas are synthetic-profile-only (`sovra.profile=synthetic`). The
SD-JWT VC profile, VCI/VP transports, and DCQL stay legacy
adult-status-only; new-schema success implies no SD-JWT conformance.

## Two-database sovereignty (outside backend ownership)

For a sovereignty claim the demo orchestrator must additionally provide:
two Postgres deployments with per-issuer credentials and no cross-DB
grants; node A wired to DB A and node B to DB B; the same trust proposal
applied on both (or a shared federation read path carrying only public
metadata, never private keys); and evidence that issuer A cannot query
issuer B's store even as superuser and cannot sign as B (refusal logs
plus the committed cross-signing regression). Until that exists, describe
the setup as logically separated authorities on shared infrastructure.
