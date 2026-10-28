# SOV-016 vault assessment (G1 synthetic)

Date: 2026-10-28. Verdict: **implemented for the synthetic scope**
with the explicit gaps below. SOV-016 stays open until its tracker
([issue](https://github.com/apil-khadka/Sovra/issues/21)) is reviewed
against this evidence.

## What was built

Envelope AEAD per object version (`dev.sovra.vault`, V14):

- Fresh random 256-bit DEK and 96-bit nonce per version;
  AES-256-GCM content seal with identity-bound AAD (tenant,
  issuer, object, version, KEK version, content digest); DEK
  wrapped under a versioned tenant KEK with wrap context binding
  the authorized purposes. AAD uses length-prefixed framing, so
  field splits cannot be confused.
- Purpose binding is two-layered: the grant names an exact
  purpose inside the version's authorized set (checked live with
  principal, object, version, workload, expiry, revocation), and
  the read compares against the set from the AEAD-verified
  envelope — substituting the database row's purposes fails the
  wrap open first.
- Grants are short-lived (60..86400 s), version-pinned, terminally
  revocable with immediate effect; reads require the exact grant
  id. Denials carry distinct reasons (GRANT_INVALID / EXPIRED /
  REVOKED) and survive as audit evidence.
- Zero cross-request plaintext cache: DEKs and content exist only
  as method locals for the one authorized operation; revocation
  and expiry are evaluated live on every read.
- Separated duties: ingest/grant (ISSUER_OPS), content read
  (TENANT_MEMBER/ISSUER_OPS through grants only), metadata
  (+AUDIT_READER, never content), KEK rotation and deletion
  (TRUST_ADMIN). Relying parties are excluded from source reads
  (INV-11). Policy rules v9.
- Runtime role: SELECT/INSERT on vault tables, column-narrowed
  UPDATE (status, revoked) only; sealed columns, DELETE, and
  TRUNCATE are denied (`LeastPrivilegeTests`).
- KMS-shaped provider seam: `VaultKekProvider` wraps/unwraps
  without exposing KEK bytes. The synthetic provider derives
  per-tenant versioned KEKs from configured seed (HKDF-SHA256,
  explicit seed + acknowledgement); the KMS stub fails loud with
  503 and no fallback. Production refuses a software provider or
  a configured seed at startup.
- Contract 0.5.0: 8 routes documented with scopes and exact
  status semantics; new Problem codes `kms_unavailable` and
  `vault_integrity_failure`.

## Evidence

- Backend `./mvnw verify`: 357/357 green, including
  `VaultFlowTests` (5: round trip, rotation lineage, revoke,
  delete, 8-way concurrent versions), `VaultNegativeTests` (17:
  role exclusion, grant confusion, expiry, widening, tenant
  isolation, tamper/substitution fail-closed, bounds, 404s,
  outage atomicity), and the vault least-privilege block.
- `scripts/e2e-vault.py`: PASS against compose (seal, metadata
  identity-only, granted read, confusion matrix, revocation,
  expiry, tamper fail-closed, rotation lineage).
- `e2e-verification` (synthetic) and `e2e-bff-login` re-passed on
  the vault build.

## Gaps that stay open

1. **Production KMS/HSM** (SOV-004 G2 pick, SOV-038): production
   vault is fail-closed (unbootable) until the attested adapter
   lands. The software seed deterministically derives every KEK
   version — seed compromise is total, which is why production
   refuses it.
2. **Wrapping-key retirement/rewrap**: the status column exists
   but G1 never retires; old versions unwrap forever. Lifecycle
   drills (SEC-44) arrive with rewrap.
3. **Byte purge**: delete is a terminal status; purging bytes
   stays a reviewed owner operation with no API.
4. **BFF/human reads**: grants accept `human_membership`
   principals, but no BFF vault endpoints exist yet; holder
   viewing (FR-40) is machine-API only.
5. **Workload attestation**: workload is an exact-matched grant
   field bound to a provisioned principal, not an independently
   attested identity (arrives with SOV-038 Confidential Space).
6. **Real-data release evidence** (SOV-038 denial cases) and the
   OD-12/OD-13 approvals predate any non-synthetic use, per the
   acceptance criteria.
