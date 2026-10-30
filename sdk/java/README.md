# Sovra Java SDK

Typed client for the Sovra machine API (contract `0.16.0`, see
`docs/engineering/implemented-api.openapi.yaml`). Covers the
machine chain only: ops, trust, auth, issuance, consent,
verification, vault, quarantine, extraction, enrollment, custody.
It does not cover BFF sessions, OpenID4VCI/VP, or browser flows.

Requires Java 25. Depends on Jackson and (for tests) JUnit/AssertJ.

```java
try (SovraClient client = new SovraClient("https://sovra.example", token)) {
  OpsClient.Health health = client.ops.health();
  IssuedCredential issued = client.issuance.issue(
      Idempotency.mint(), issuerId, vct, holderJwk, holderProof,
      Map.of("adultOver18", true), expiresAt, null);
}
```

Rules (OD-16):

- Base URL must be HTTPS, or HTTP loopback for local demos.
- Reads retry at most 3 times on transport failure or 503.
- Writes never retry automatically. Replays resend the original
  idempotency key; fresh operations mint fresh keys.
- Failures throw `SovraApiError` with status, server code, and a
  token-scrubbed message. `retryable()` marks transport-level
  failures only.
- Conditional reads return `Optional.empty()` on 304.

## Live-stack tests

Every test talks to a real backend:

```sh
docker compose up --build -d
JAVA_HOME=$HOME/.sdkman/candidates/java/25.0.2-tem \
  ./backend/mvnw -f sdk/java/pom.xml test
```

`SOVRA_SDK_BASE` (default `http://localhost:8080`),
`SOVRA_E2E_DB_CONTAINER` (default `sovra-db-1`), and
`SOVRA_DB_ADMIN_PASSWORD` (default `sovra-dev-only`) point the
suite at the stack. Tests mint throwaway service accounts through
the compose database and leave the trust snapshot carrying every
issuer they found (read-modify-write), so reruns are safe.
