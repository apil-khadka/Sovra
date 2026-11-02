# KYC demo relying-party apps

Two mock verifier apps show Sovra's consent + verification chain working
end to end: **NovaBank** (demo bank onboarding) and **CornerCellar**
(age-gated demo shop). Both live in [`demo/`](../../demo/) with their own
[README](../../demo/README.md).

## What each app shows

NovaBank walks a visitor through requesting age eligibility, reviewing
the exact bound values (RP, purpose, `adultOver18: true`, synthetic
issuer, expiry), approving or declining with a browser-generated holder
key, and receiving an ACCEPTED/REJECTED/UNKNOWN decision with a receipt
(decision id, reason code, trust snapshot version, profile).

CornerCellar runs the same chain inside a checkout story: a basket with
one 18+ item, an age gate, and gating outcomes (order placed on ACCEPTED,
item held on decline or rejection, retry on UNKNOWN).

Each app carries a synthetic-demo banner on every screen, a
not-legal-KYC/AML line on the consent screen, and an ops corner fed by
the RP outcomes/metrics endpoints.

## Run

From the repository root, with the synthetic compose stack up and live
planning disabled:

```sh
pnpm --dir demo run setup
pnpm --dir demo start
```

Then open `http://localhost:5174` in a browser. The server refuses to
boot against a non-synthetic backend. `pnpm --dir demo run smoke`
replays approve, deny, and metrics flows headlessly.

## For integrators

The third RP is [`demo/minimal/`](../../demo/minimal/server.mjs): one page
plus one zero-dependency server, built to be copied. Start it with
`pnpm --dir demo run minimal`, open `http://localhost:5175`, then read
the [RP quickstart](integrate-age-check.md) for the four calls, nonce
discipline, UX states, and retry rules.

## Boundaries

- Synthetic fixtures only; fictional RP and issuer identities.
- The mock apps are verifiers, never issuers or authorities.
- No real KYC/AML, biometrics, document handling, sanctions screening,
  payments, production data, or conformance claims — see
  [claims-and-limitations.md](../compliance/claims-and-limitations.md).
