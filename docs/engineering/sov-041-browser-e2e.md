# SOV-041 real-browser E2E decision (G1 synthetic)

Date: 2026-10-29. Status: implemented. This records the browser
automation harness that the [continuation
guide](continuation-guide.md) step 3 asked for. It does not close
SOV-041: the selected protocol profile (SOV-036) and its
full-profile browser evidence are still outstanding.

## Harness

Playwright Test, pinned exact in `frontend/package.json`
(`@playwright/test`), Chromium only, specs in `frontend/e2e/`.
No separate web driver and no `/etc/hosts` edit: the Playwright
config maps `sovra-keycloak` to loopback with
`--host-resolver-rules`, so the real browser reaches the real
Keycloak hostname exactly as a demo machine would with the
documented hosts line. CI runs the same suite in the `browser-e2e`
job of `.github/workflows/app-checks.yml` against a disposable
compose stack (`docker compose up --build -d`, torn down with
`down -v` afterwards).

```sh
docker compose up --build -d
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend exec playwright install chromium
pnpm --dir frontend run test:e2e
```

Global setup fails fast unless the packaged origin reports READY,
then mints one disposable machine account in `sovra-demo` for the
server-side actors (issuer minting, RP request creation) via the
same `docker exec` psql path as `scripts/e2e-verification.py`.
Every holder proof — consent decision, binding proof — is produced
by WebCrypto inside the page through the real React UI: the holder
key is generated in the browser, exported through the real
clipboard button, and issuance binds that same thumbprint.

## Scope

Eleven tests across login, consent, and verification:

- Member login through the real Keycloak form (PKCE S256
  asserted), session roles shown, logout back to the same origin
  with no session left, and a fresh login proving the provider SSO
  session died too.
- Password-only privileged login withholds `TRUST_ADMIN`; wrong
  password shows the Keycloak error and creates no session;
  anonymous and machine-token BFF reads are rejected.
- Holder reviews the exact bound relying party, audience, purpose,
  claims, plan hash, challenge, and holder thumbprint, then
  approves (WebCrypto-signed) or denies; denial leaves no
  presentation behind.
- A non-matching holder key disables approval in the UI; a
  decision POST without the CSRF echo is rejected while the UI
  echo succeeds; anonymous consent reads fail closed.
- The imported holder key, a fresh UI nonce, and the consented
  audience verify to ACCEPTED with the stored decision re-read
  identically; a mismatched audience rejects.

## Explicit non-scope

Expiry waits, proof tampering, concurrent replay, kill/restart
recovery, and the wrong-issuer/revoked-credential matrix stay with
the two-instance HTTP suites (`scripts/e2e-verification.py`,
`scripts/e2e-bff-login.py`) and the backend unit tests, which cover
different boundaries and remain green alongside this suite.
Consent-request expiry bounds are asserted in
`ConsentNegativeTests`/`VerificationNegativeTests`, not by waiting
out a lifetime in the browser.

## Observed behavior

After the Keycloak callback the browser lands on the saved request
(`http://localhost:8080/api/bff/me?continue`) rather than `/`:
same origin, live session, but raw JSON until the user returns to
`/`. The suite asserts the origin and session, then navigates to
`/` like the human demo. Changing the landing target is a UX
decision left untouched by this stage.
