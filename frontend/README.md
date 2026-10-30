# Sovra frontend

React, TypeScript and Vite provide synthetic demo, holder consent and verification screens.
The backend container packages the production bundle, so SPA, BFF session, authorization callback and logout share `http://localhost:8080` locally.
The Vite server on port 5173 is for asset development; use the packaged origin for login E2E.

```sh
pnpm install --frozen-lockfile
pnpm run typecheck # checks application, tooling and E2E project references
pnpm run build     # typechecks and builds the production bundle
pnpm run lint
pnpm run dev
```

Keep `pnpm-lock.yaml` pinned as the reproducible dependency record.

## Browser E2E

Playwright and Chromium specs live in `e2e/`.
From the repository root:

```sh
SOVRA_AI_LIVE_ENABLED=false SOVRA_AI_API_KEY='' SOVRA_AI_BASE_URL='' SOVRA_AI_MODEL='' docker compose up --build -d
pnpm --dir frontend exec playwright install chromium
pnpm --dir frontend run test:e2e
```

Use a disposable synthetic database: global setup creates a machine account and the tests create journey records.
The suite drives real Keycloak login, direct SPA landing, holder consent, signed native verification, tampering/wrong-holder rejection and replay.
Issuer/RP setup uses the disposable machine account; holder consent and verification proofs use WebCrypto in the page.

Overrides are `SOVRA_BROWSER_BASE` (default `http://localhost:8080`), `SOVRA_E2E_DB_CONTAINER` (default `sovra-db-1`) and `SOVRA_DB_ADMIN_PASSWORD`.
The native verifier screen implements the synthetic binding.
The OpenID demo wallet implements the SD-JWT pre-authorized issuance/consent/encrypted-presentation journey with in-memory holder custody.
For that journey, start Compose with `SOVRA_PROFILE=sdjwt-vc` and pass the same variable to the browser command.
Both application instances must use the selected profile; keep live AI disabled as above.
CI runs both profiles separately with live provider access disabled.
See [wallet scope and limitations](../docs/engineering/sov-041-browser-wallet.md).
See [browser evidence](../docs/engineering/sov-041-browser-e2e.md) and the [continuation guide](../docs/engineering/continuation-guide.md).
