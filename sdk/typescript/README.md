# Sovra TypeScript SDK

Typed client for the Sovra machine API (contract `0.14.0`, see
`docs/engineering/implemented-api.openapi.yaml`). Covers the
machine chain only: ops, trust, auth, issuance, consent,
verification, vault, quarantine, extraction, enrollment, custody.
It does not cover BFF sessions, OpenID4VCI/VP, or browser flows.

Requires Node.js 22+. Zero runtime dependencies.

```ts
import { SovraClient, mintIdempotencyKey } from "@sovra/sdk";

const client = new SovraClient({ baseUrl: "https://sovra.example", token });
const health = await client.ops.health();
const issued = await client.issuance.issue({
  idempotencyKey: mintIdempotencyKey(),
  issuerId,
  vct,
  holderJwk,
  holderProof,
  claims: { adultOver18: true },
  expiresAt,
});
```

Rules (OD-16, same as the Java SDK):

- Base URL must be HTTPS, or HTTP loopback for local demos.
- Reads retry at most 3 times on transport failure or 503.
- Writes never retry automatically. Replays resend the original
  idempotency key; fresh operations mint fresh keys.
- Failures throw `SovraError` with status, server code, a
  token-scrubbed message, and a `retryable` flag.
- Conditional reads resolve `undefined` on 304.

## Live-stack tests

Every test talks to a real backend:

```sh
docker compose up --build -d
npm --prefix sdk/typescript ci --no-audit --no-fund
npm --prefix sdk/typescript test
```

`SOVRA_SDK_BASE` (default `http://localhost:8080`),
`SOVRA_E2E_DB_CONTAINER` (default `sovra-db-1`), and
`SOVRA_DB_ADMIN_PASSWORD` (default `sovra-dev-only`) point the
suite at the stack. Tests mint throwaway service accounts through
the compose database and leave the trust snapshot carrying every
issuer they found (read-modify-write), so reruns are safe.
