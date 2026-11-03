# Dual-issuer demo topology (standalone, local, synthetic)

Two genuinely separate local issuer stacks for the governed
unfamiliar-schema demo — not the root harness's `app-a`/`app-b`, which
share one PostgreSQL. Node A serves `synth-1` from database A; node B
serves `synth-2` from database B.

| | Node A | Node B |
| --- | --- | --- |
| App URL | `http://127.0.0.1:8280` | `http://127.0.0.1:8281` |
| Serves issuer | `.../issuers/synth-1` | `.../issuers/synth-2` |
| Key held | P-256 scalar 1 (`synth-1:v1`) | P-256 scalar 3 (`synth-2:v1`) |
| Database | `db-a` (own volume) | `db-b` (own volume) |
| Network | `sovra-demo-a-net` (10.245.0.0/24) | `sovra-demo-b-net` (10.246.0.0/24) |
| Demo tenant | `demo-issuers-a` | `demo-issuers-b` |

Source file: `compose.demo-issuers.yaml` (project `sovra-demo-issuers`).
It reuses the backend Dockerfile and `db/init` role scripts, but nothing
else is shared with the root stack: separate project, volumes,
networks, credentials, and vault seeds. Ports are localhost-only and
avoid the root (8080/8081, Keycloak 18080) and demo (5174/5175) ports.
Postgres publishes no host ports; operators use `docker exec` only.

## Honesty boundary

The host operator can reach both stacks — this is one developer
machine, and the shared host orchestrator obviously retains control.
Each app process holds ONLY its own DB credential and key, but no
claim is made of host/root isolation, production sovereignty, or any
inability of an omnipotent host admin to access both sides. The demo
evidence is local and operational: independent stores, per-node key
selection, distinct credentials, and refusal behavior. Describe the
setup in exactly those terms.

One verified caveat: the postgres image trusts loopback connections
*inside* each container (`pg_hba` trust for `127.0.0.1`/`::1`, same
as the root stack), so a probe over `127.0.0.1` would accept even a
wrong password and prove nothing. The cross-DB check therefore
connects to each database's bridge address, where `scram-sha-256`
applies: foreign credentials are rejected, own credentials accepted.
That proves the roles carry different SCRAM secrets — it does not
harden the container's own loopback.

## Request routing

- **Planning goes to ONE central node/ledger: node A.** All
  `POST /api/plans/propose` calls (known, fjord/harbor scoped, and
  employment scoped) target node A. Never arm both nodes independently
  on the same provider account.
- **Guard** runs on node A alongside planning (same snapshot content).
- **Issuance, consent, and verification route by the ACTUAL plan
  issuer** to the corresponding node with that node's own token:
  `candidate_issuer_id .../synth-1` → node A, `.../synth-2` → node B.
  The demo client must pass the returned plan object through verbatim —
  no fixed template — and use the per-node RP/issuer tokens below.
- Node A refuses `synth-2` signing requests and node B refuses
  `synth-1` (committed `CrossSigningTests` behavior, re-verified live
  by check 09 of `qualify-runtime.py`). The two legs refuse at
  different layers, pinned exactly: node A answers HTTP 400
  `invalid_request` (its registry names only `synth-1`, so the gate
  fires before any crypto), while node B answers HTTP 500 `internal`
  (the genesis migration seeds an ACTIVE `synth-1` registry row on
  every fresh database including B's, so the registry gate passes
  and node B's signer — which holds only the `synth-2` scalar —
  refuses the unknown key; the backend's own migration comment
  blesses this backstop: "registration alone grants nothing"). The
  check requires node B's `signer refused a signing call` log marker
  to increase, so an unrelated 500 bug cannot masquerade as the
  backstop. Revoking the genesis row instead would be wrong:
  revocation poisons JWKS and verification while the key is not
  compromised.

## Trust vs. artifacts: what is shared, what stays local

- **Public trust metadata is synchronized, not shared infrastructure:**
  the same two-person proposal/approve/activate flow runs on BOTH
  databases, so both snapshots authorize both issuers with identical
  public entries (issuer ids, types, key ids, public JWKs, validity
  windows — the provisioner canonicalizes the window edges because
  each genesis store minted its own at migration time). Either
  node can therefore plan and guard over the full federation picture.
  Qualification compares snapshot contents field by field (check 11);
  equal version numbers alone prove nothing.
- **Private artifacts stay local:** each credential row, idempotency
  record, consent, and verification decision lives only in the issuing
  node's database. `db-A` must hold only `synth-1` rows and `db-B`
  only `synth-2` rows (check 09). Signing keys likewise never leave
  their node: each signer holds its scalar in memory only, and only
  public JWKs travel (registry read-back at provision time, JWKS at
  runtime).

## Bring-up order

Start the app stacks FIRST so boot runs the Flyway migrations, then
bootstrap accounts, provision trust, and qualify. (`bootstrap.py
--phase db` inserts into `tenant`/`service_account` and refuses to run
until those migrated tables exist — app health `UP` is enough, full
`READY` is not required yet.)

1. `docker compose -f compose.demo-issuers.yaml config --quiet`
2. `docker compose -f compose.demo-issuers.yaml up -d --build`
3. `python3 scripts/demo-issuers/bootstrap.py`
   (db accounts, then server-side RP/issuer mint; or run
   `--phase db` and `--phase rp` separately)
4. `python3 scripts/demo-issuers/provision-trust.py`
5. `python3 scripts/demo-issuers/qualify-runtime.py`

To start databases alone first (for inspection): `up -d db-a db-b`,
then step 2 for the full stacks. Never run `docker compose down -v`
on this file (it would destroy both demo databases); `stop`/`down`
without `-v` preserves volumes. Never touch the root stack's
containers, tokens, or volumes from this lane.

## Credentials (development-only)

Compose defaults are non-secret dev literals, distinct per node and
from the root stack; override with `SOVRA_DEMO_{A,B}_DB_ADMIN_PASSWORD`,
`SOVRA_DEMO_{A,B}_APP_DB_PASSWORD`, `SOVRA_DEMO_{A,B}_VAULT_SEED`.

API tokens are minted by `bootstrap.py` into files only
(default `/tmp/sovra-demo-issuers/tokens/`, dir 0700, files 0600):

- `{a,b}-maker.token`, `{a,b}-checker.token` — TRUST_ADMIN maker/checker
  (trust provisioning only; distinct identities per database).
- `{a,b}-setup.token` — TRUST_ADMIN operator-held provisioning token.
  Used ONCE by `bootstrap.py --phase rp` to mint the runtime
  credentials below. NEVER given to the runtime demo server — no
  admin token belongs in demo-server config.
- `{a,b}-rp.token` — RP_CLIENT (plan/guard/consent/verify), 24h expiry.
  The demo server's `rpToken` per node.
- `{a,b}-issuer.token` — ISSUER_OPS + TENANT_MEMBER (issuance), 24h
  expiry, same tenant as the RP account. The demo server's
  `setupToken`/issuance credential per node (despite the name, this
  is the runtime issuance token — not the admin setup token above).

No token is printed, committed, or embedded in tracked files. The
RP/issuer tokens expire in 24h; re-run `bootstrap.py --phase rp` to
rotate (old same-name rows are revoked first).
