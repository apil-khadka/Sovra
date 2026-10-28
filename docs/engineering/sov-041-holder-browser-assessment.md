# SOV-041 holder/browser path assessment (G1 synthetic)

Date: 2026-10-28. Verdict: **SOV-041 stays open.** The packaged
HTTP evidence below is necessary but not sufficient: the acceptance
criterion requires the *actual holder consent/browser path*, which
no current check drives through a real browser DOM/JS stack.

## What the criterion requires

Backlog SOV-041, acceptance 1: "Run the packaged selected-profile
issuer, actual holder consent/browser path and verifier over HTTP
with real PostgreSQL and two backend instances; a Python signature
check alone is not this verification test."

## Evidence present (2026-10-28, this tree)

- `scripts/e2e-verification.py`: PASS in both `synthetic` and
  `sdjwt-vc` profiles — two instances, real PostgreSQL, issue →
  consent → approve → presentation → ACCEPTED, byte-identical
  cross-instance replay, 8-way concurrent single-acceptance,
  negative matrix (tamper, audience, nonce, unapproved/denied
  consent, conflict, revoked credential, cross-tenant 404), plus
  instance-restart and DB-restart recovery with identical replay.
  HTTP-level only: holder proofs are minted by the script, not by
  a holder agent in a browser.
- `scripts/e2e-bff-login.py`: PASS against compose Keycloak —
  member login lands a TENANT_MEMBER session, password-only
  privileged login withholds TRUST_ADMIN, wrong password yields
  no code, machine Bearer [REDACTED] rejected on the BFF, logout kills the
  session with an OP logout URL. Scripted HTTP form submit, not a
  real browser (no JS/DOM): Keycloak form behavior under JS is
  unexercised.
- SPA mapping: `pnpm dev` serves the app (200), `/api` proxies to
  app-a (health UP, `/api/bff/me` 401 anonymous), `/oauth2` and
  `/login` proxy the login chain (302 to Keycloak with S256
  PKCE). Verified by curl, not by a browser render.
- Backend `./mvnw verify`: 307/307 green, including BFF login (9),
  holder flow (4), and API-contract parity at 0.4.0.

## Gaps that keep SOV-041 open

1. **No real-browser holder journey.** Nothing drives
   login → consent review → approve → verification through
   rendered DOM/JS. No browser automation exists in this
   environment (no Playwright/Puppeteer/Chromium), and the demo
   realm login forms are only exercised as raw HTML posts.
2. **SPA serving/origin undecided.** The frontend assumes
   same-origin with the backend, but nothing serves the built SPA
   from app-a: the dev proxy covers local work while the
   registered OIDC callback and post-login landing stay on
   `localhost:8080`. A real-browser pass must first decide
   Spring-static serving vs. a same-origin gateway, then register
   and test exactly that origin — no redirect/origin change
   without re-running the browser evidence.
3. **Profile scope.** The HTTP suite covers both G1 profiles, but
   SOV-036 protocol/conformance gaps (OpenID4VCI/VP flows,
   third-party wallet fixtures) bound what "selected-profile"
   holder evidence can claim: BFF-session holder only, no
   external wallet.

## Demo loop as of now (manual, unscripted)

1. `docker compose up --build -d`, wait for both
   `/api/health/ready` to return 200.
2. `pnpm --dir frontend dev` → open `http://localhost:5173`.
3. Log in with a demo account; the Keycloak callback lands on
   `http://localhost:8080/` (registered redirect). Return to
   `:5173`: the host-scoped session cookie carries over.
4. Drive consent/verify views as the session caller.

Step 3's origin hop is the visible seam of gap 2. Do not "fix" it
by widening redirect URIs ad hoc; decide the serving origin
first, then register exactly it.
