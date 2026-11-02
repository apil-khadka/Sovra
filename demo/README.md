# Sovra KYC demo apps (synthetic only)

Two mock relying-party apps that integrate with Sovra's consent +
verification chain: **NovaBank** (demo bank onboarding) and
**CornerCellar** (age-gated demo shop). Both are verifiers: they request
one fact — over 18 — and never see documents, birth dates, or source
profiles. Every issuer, holder, credential, and account is synthetic.

See [kyc-demo-apps.md](../docs/demo/kyc-demo-apps.md) for the reviewed
run guide and [claims-and-limitations.md](../docs/compliance/claims-and-limitations.md)
for what these demos must never claim.

## Run

```sh
# 1. Synthetic Sovra stack (from the repository root)
SOVRA_AI_LIVE_ENABLED=false SOVRA_AI_API_KEY='' SOVRA_AI_BASE_URL='' SOVRA_AI_MODEL='' docker compose up --build -d

# 2. Demo credentials (disposable; stored in demo/.env.local, gitignored)
pnpm --dir demo run setup

# 3. Demo server (zero dependencies; refuses non-synthetic backends)
pnpm --dir demo start
```

Then open [http://localhost:5174](http://localhost:5174) in a browser and
pick NovaBank (`/novabank`) or CornerCellar (`/cornercellar`).

The copy-paste starting point for integrators is `demo/minimal`
([quickstart](../docs/demo/integrate-age-check.md)):

```sh
pnpm --dir demo run minimal
```

Then open [http://localhost:5175](http://localhost:5175) in a browser.

Headless checks without a browser:

```sh
pnpm --dir demo run smoke      # NovaBank
pnpm --dir demo run smoke:all  # NovaBank + CornerCellar + minimal
```

## Architecture

- `server.mjs`: tiny RP backend (plain `node:http`). Holds the two
  sandbox RP tokens plus the setup token; browsers never see them. Forwards
  signed holder bytes to Sovra and enforces each app's own audience.
- `public/shared.js`: isomorphic demo engine (holder keys, ES256
  signatures, canonical messages, flow runner). Shared by both pages and
  the smoke test.
- `public/novabank.html`, `public/cornercellar.html`: the two mock apps.
  Same engine, different story and copy.
- `setup.mjs`: mints the disposable setup account plus both sandbox RP
  accounts through the real product endpoint.
- `limit.mjs`: shared origin check plus per-IP token bucket, used by
  both servers. Coarse abuse protection (foreign origins rejected,
  quotas with `Retry-After`, 64KB bodies, 10s upstream deadline) —
  not a production WAF. Public hosting still needs a hosting
  decision (PROD-006).

## Out of scope

Real KYC/AML, biometrics, document upload, sanctions screening,
government-ID handling, payments, production data, and any conformance
claim. The demos prove a technical flow over synthetic fixtures only.
