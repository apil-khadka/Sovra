# Production key services (PROD-005)

## What exists

- `dev.sovra.kms.KmsProvider`: the G2 seam. One interface for
  issuance signing and vault wrap/unwrap, every call carrying an
  attested `KmsCallContext` (workload, image digest, location,
  single purpose, key reference). No raw or generic entry exists.
- `KmsSigner` / `KmsVaultKekProvider`: the kms-mode beans. They
  delegate with per-call attested contexts built from
  `sovra.kms.*` configuration. The provider dependency is
  required — with no G2 bean, kms-mode boot fails instead of
  failing per request.
- Denials vs outages: `KmsDeniedException` (wrong caller, purpose,
  key, revoked, tampered bytes) maps to an opaque 500;
  `KmsUnavailableException` (network, quota, provider error) maps
  to retryable 503. Vault unwrap denials become
  `VaultAuthenticationException`, preserving seal-failed semantics.
- `KmsProviderConformanceTests` (test sources): the executable
  acceptance contract — happy-path round-trips, all four
  attestation denials, unknown/revoked keys, AAD and ciphertext
  tampering, purpose crossing, and a 16-thread latency smoke.
  `TestKmsProvider` (test sources, real ECDSA/AES-GCM) passes it;
  the G2 pick passes the same suite against the real KMS. The
  suite is the handoff: subclass, point at the provider, run.
- Attestation configuration is required: the production entry
  gate refuses blank `sovra.kms.workload` / `image-digest` /
  `location`, and the production compose marks all three `:?`
  required. Unattested operation cannot boot.
- OpenID4VP verifier keys: `VerifierKeys` has two implementations,
  never both. Demos use the deterministic scalar-2 fixture
  (flag-gated, bean absent otherwise); production uses
  `FileVerifierKeys` — random P-256 pairs from read-only PEM
  mounts, separate signing/decryption keys with versioned kids,
  overlap decryption across rotation. The entry gate requires
  `sovra.openid.keys=file`; missing files fail boot.
- Worker KEK: `WorkerKekProviders` resolves demo software
  explicitly and fails every other combination with an actionable
  message. Production+kms fails until a worker KMS implementation
  registers — there is no fallback that could be mistaken for one.
- Status evidence: `SyntheticStatusService` reads the local
  revocation registry with no fixture fallback and no flags, so it
  is production-valid for Sovra-issued credentials as the
  registry source. Privacy-preserving Token Status List stays a
  G2 protocol item, not a key-seam gap.

## What G2 still owns (after SOV-037/038/039 approvals)

1. Provider pick + `KmsProvider` bean (workload attestation via
   the platform identity system, image digest from the release
   pipeline, location from topology).
2. Conformance run against the real KMS, including the latency
   smoke at staging concurrency; record quotas and p99, set
   alerts, size admission budgets from the numbers.
3. Rotation: add key version, overlap decrypt/verify, promote,
   revoke old — the suite's revocation cases prove the denial
   side; run the full dance on staging.
4. Revocation and independent recovery: revoke a live key,
   confirm denials within the propagation bound, recover from the
   provider's backup/export without the application cluster.
5. Worker KMS KEK implementation + re-enable the worker service
   in the production compose (currently omitted by design).

## Key inventory (production)

| Key | Home | Rotation |
|---|---|---|
| Issuer signing (ES256) | KMS (G2) | Versioned `kid`s; JWKS overlap, then revoke. |
| Vault KEKs (per tenant) | KMS (G2) | `kek_version` bump; old versions unwrap-only until re-wrap. |
| VP signing (ES256) | `/run/sovra/keys/vp-sign.pem` | New file + kid, rolling restart. |
| VP decryption (ECDH) | `/run/sovra/keys/vp-dec-*.pem` | Overlap list (current, previous), restart, drain, drop. |
| Keycloak realm (ES256) | Keycloak providers | Overlap priority, JWKS settle, remove (see runbook). |
| Service-account tokens | DB hashes | Rotate API; old prefix dies with the row. |
