# SOV-036 third-party fixtures

These vectors simulate wallet/issuer/verifier peers that share no code
with Sovra's walt-id path: every artifact is minted by `NimbusWallet`
(Nimbus JOSE + JDK only) or checked in below.

- `third-party-issuer-jwks.json`: public half of the simulated external
  issuer `https://issuer.example/third-party-1` (P-256 scalar 3, key
  `third-party-1`). The private scalar lives only in the test that
  mints with it; it is as non-secret as the synthetic issuer scalars
  and must never leave fixture use. The issuer is deliberately absent
  from every trust snapshot, so presentations under its key must
  reject with `ISSUER_KEY_INACTIVE` (crypto path) or `invalid_request`
  (wrong credential for the VP session).
- Credentials are minted at test time with dynamic validity windows
  (no checked-in expiry time bombs); the key is fixed so vectors are
  reproducible.
