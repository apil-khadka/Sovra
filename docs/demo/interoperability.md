# Interoperability demo (unfamiliar schemas)

One proof across four issuer schemas: the planner discovers how to prove
over-18 from unfamiliar credentials at runtime, the deterministic guard
adjudicates the returned plan, and issuance/consent/verification run
against the plan's own issuer. Page: `/interoperability` on the demo
server (`demo/public/interoperability.html`, engine
`demo/public/shared.js`, core `demo/interop.mjs`).

The normative API contract is
[implemented-api.openapi.yaml](../engineering/implemented-api.openapi.yaml).
The two-node deployment this page can run against is documented in
`dual-issuer-topology.md` next to this file. Nothing here overrides them.

## The four cases

All cases use semantic outcome `age_over_18` and send the canonical hint
`requestedClaims: ["adultOver18"]` — never the to-be-discovered wire
field, so an echo proves nothing and discovery must happen inside the
planner over approved metadata.

| Case | Policy | Scope | Expected |
| --- | --- | --- | --- |
| `known` | `sovra-synthetic-policy/age-check` v1 | issuer synth-1 + type adult-status/1 (omitted on legacy backends) | `CANDIDATE_ONLY` synth-1 plan, guard accepts |
| `fjord` | `sovra-synthetic-policy/age-check-mapped` v1 | issuer synth-2 + type fjord-adult/1 | `CANDIDATE_ONLY`, `claim_paths: ["isAdult"]` from the returned plan |
| `harbor` | `sovra-synthetic-policy/age-check-mapped` v1 | issuer synth-2 + type harbor-adult/1 | `CANDIDATE_ONLY`, `claim_paths: ["qualifiesAsAdult"]` |
| `employment` | `sovra-synthetic-policy/age-check-mapped` v1 | issuer synth-2 + type employment-tenure/1 | Actual HTTP 200 `NO_PATH`, null plan — no guard call, no credential, no consent |

Scope is three flat optional arrays (`scopeIssuerIds`,
`scopeCredentialTypes`, `scopeJurisdictions`); there is no nested scope
object and no empty-claims form. The page passes the ACTUAL returned
plan object into guard/consent/verify and binds its canonical
`sovra-plan/v1` hash — no fixed template anywhere.

## Routing

- Planning (`POST /api/plans/propose`) and guard
  (`POST /api/guard/validate`) go to ONE central node/ledger.
- Issuance, consent, decision, and verification route by the ACTUAL
  returned plan issuer to the node holding that issuer's key, with that
  node's own tokens. Cross-issuer requests are refused, never rerouted.
- The server holds each guarded plan, policy, hash, and scope in a
  bounded opaque transaction (10 minutes, 500 entries max). The browser
  references the transaction id only: it cannot substitute issuer,
  type, plan, hash, token, or URL. Minted credential and request ids
  bind to the transaction; unknown, expired, or over-capacity
  transactions are refused.

## Honesty rules (enforced, not aspirational)

- `LIVE` appears only when a backend response actually says so;
  `FIXTURE` is shown prominently otherwise. Mode is backend-global:
  the page has no mode toggle and never relabels a response.
- Tool counts and citations come only from backend responses. The page
  invents no tool trace and no reasoning transcript.
- Unavailable backends answer `503`/pending with the reason shown;
  nothing falls back to fixtures silently. A `400` is input validation,
  never refusal evidence — only an actual 200 `NO_PATH` refusal counts.
- Holder keys stay in page memory; machine tokens stay on the server.
  All backend- or model-supplied strings render as inert text.

## Run

The four-case unfamiliar-schema journey needs the standalone dual-issuer
topology, whose two databases and cross-sign refusal checks are described
in [dual-issuer-topology.md](dual-issuer-topology.md).
From the repository root, start and qualify that synthetic topology with
live planning explicitly disabled:

```sh
docker compose -f compose.demo-issuers.yaml config --quiet
SOVRA_AI_LIVE_ENABLED=false docker compose -f compose.demo-issuers.yaml up -d --build
python3 scripts/demo-issuers/bootstrap.py
python3 scripts/demo-issuers/provision-trust.py
python3 scripts/demo-issuers/qualify-runtime.py
```

Then start the interop-only demo server with the per-node runtime tokens
created by bootstrap:

```sh
SOVRA_BASE=http://127.0.0.1:8280 \
SOVRA_BASE_SYNTH2=http://127.0.0.1:8281 \
SOVRA_DEMO_TOKENS_DIR=/tmp/sovra-demo-issuers/tokens \
PORT=5176 \
pnpm --dir demo start
```

Open `http://localhost:5176/interoperability` and pick a case.
The page reports `FIXTURE`; planning stays disabled for live AI.
The distinct-node qualifier is repeatable after bootstrap without
deleting either demo database or its volumes.

The public demo view links to the local server on port 5174 when the
app is opened from a loopback hostname.
For a deployed same-origin route, serve `/interoperability` through the
edge; otherwise set `VITE_SOVRA_INTEROP_DEMO_URL` at frontend build time
to the approved demo URL.

Headless contract tests (fake backend, no network, no model):

```sh
pnpm --dir demo test
```

Real-browser verification + captioned recording (live demo server and
backend nodes, repo-pinned frontend Playwright, system ffmpeg for the
MP4; artifact paths configurable, no private files required):

```sh
DEMO_BASE=http://127.0.0.1:5176 ARTIFACT_DIR=/tmp/sovra-interop-browser \
  pnpm --dir demo run verify:browser
DEMO_BASE=http://127.0.0.1:5176 ARTIFACT_DIR=/tmp/sovra-interop-demo \
  pnpm --dir demo run record:demo
```

## Configuration contract (names and paths only, never values)

Environment wins, `demo/.env.local` (ignored) supplies the rest, and
per-node token files apply ONLY when `SOVRA_DEMO_TOKENS_DIR` is
explicitly set — files that merely appear on disk are never
auto-loaded. The server reads only these RP/issuer basenames —
`a-rp.token`, `a-issuer.token`, `b-rp.token`, `b-issuer.token` — never
TRUST_ADMIN setup/maker/checker files, which are provisioning-only.

- `SOVRA_BASE` — central ledger URL (default `http://localhost:8080`).
- `SOVRA_BASE_SYNTH2` — second issuer node URL (default: same as central).
- `SOVRA_DEMO_TOKENS_DIR` — explicit token directory (no default):
  `<dir>/a-rp.token`, `<dir>/a-issuer.token`, `<dir>/b-rp.token`,
  `<dir>/b-issuer.token`. The dual-issuer topology writes
  `/tmp/sovra-demo-issuers/tokens/{a,b}-{rp,issuer}.token`.
- `SOVRA_A_RP_TOKEN`, `SOVRA_A_ISSUER_TOKEN` — inline node A credentials.
- `SOVRA_B_RP_TOKEN`, `SOVRA_B_ISSUER_TOKEN` — inline node B credentials.
- `INTEROP_RP_TOKEN` — node A RP fallback in single-node mode.

Modes: with the default base and a legacy `demo/.env.local` the server
boots full (NovaBank/CornerCellar plus interop sharing the root store).
With an explicit `SOVRA_BASE` plus node credentials it boots
interop-only and legacy routes answer `503 legacy_unconfigured` rather
than misrouting root tokens to the new store. A differing
`SOVRA_BASE_SYNTH2` requires its own B credentials; without them the
status reports synth2 unconfigured and synth-2 flows fail closed with
`issuer_node_unconfigured` — B never inherits A tokens across stores.

```sh
# Legacy single-node (default root store)
pnpm --dir demo run setup
pnpm --dir demo start

# Fresh dual-node interop-only (URLs and token paths only)
SOVRA_BASE=http://127.0.0.1:8280 \
SOVRA_BASE_SYNTH2=http://127.0.0.1:8281 \
SOVRA_DEMO_TOKENS_DIR=/tmp/sovra-demo-issuers/tokens \
pnpm --dir demo start
```

## Transaction honesty (one write per tx)

Each guarded transaction allows one issuance and one consent creation.
Simultaneous callers cannot open duplicates: identical retries coalesce
onto the single in-flight upstream call, while a changed idempotency
key or holder sees an explicit in-progress/conflict refusal. Issuance
freezes its exact upstream request (including expiry) before the first
send, so an uncertain delivery (timeout after a possible commit)
retries byte-identically under the same key and never admits a new key.
Consent has no backend idempotency contract, so a lost create response
marks the tx `request_uncertain` and refuses further creates — the run
restarts from a fresh plan. Reviews require HTTP 200 with the matching
request id and exact plan hash; anything else fails closed and the
saved id retries the read, never recreates.

## Boundaries

- Synthetic fixtures only; fictional RP and issuer identities.
- The page is a verifier journey, never an issuer or authority.
- No real KYC/AML, biometrics, document handling, payments, production
  data, or conformance claims — see
  [claims-and-limitations.md](../compliance/claims-and-limitations.md).
