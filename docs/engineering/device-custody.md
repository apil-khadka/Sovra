# Durable device custody and recovery reissuance (PROD-015)

Holder keys live on devices, and theft reports name the device —
not a thumbprint the victim cannot read off a stolen phone.
`holder_device` (migration `V36__device_custody.sql`) binds each
enrollment key to a named device; enrollment approval mints the
`primary` handle, and recovery mints the named replacement. Keys
predating the table were backfilled to `primary` in the migration,
so every key has a device except server-side rotations performed
without device facts.

## Report, recover, reissue

`POST /api/holder-devices/report` takes a device id and a reason
(`loss`, `theft`, `compromise`). The device flips to
`LOST`/`STOLEN`/`COMPROMISED`, every live key on it gets its own
recovery case, and every credential those keys authorize is revoked
at once — linked to its case via
`credential_artifact.revoked_by_recovery`. Only `VALID` rows flip,
so an earlier independent revocation keeps its own link and is
never resurrected by a later recovery.

Recovery (`POST /api/holder-keys/recover`, trust admin) re-proofs
the *live case*, not the lost key: the enrollment must still be
eligible, the replacement key must prove possession over the
recovery label, and an optional `deviceLabel` binds the fresh key
to a new `ACTIVE` device.

Reissuance is recovery-scoped and split by duty: the trust admin
recovers, issuer ops reissues — neither role holds the other's
step, and reissue is impossible before recovery completes.
`GET /api/holder-recoveries/{id}/reissue-plan` lists exactly the
report-linked credentials with the deterministic idempotency key
each reissue must use; `POST .../reissue` takes a holder proof per
credential over the issuance label and mints replacements that:

- bind the replacement key and carry the enrollment's reviewed
  claims (like-for-like adult status, re-checked against the live
  case at reissue time),
- earn validity from the recovery event (deterministic, so retries
  replay instead of conflicting),
- chain to the revoked id via `credential_artifact.supersedes`.

The batch is all-or-nothing: a missing or wrong-key proof rolls
everything back. Revoked ids stay revoked forever.

## Reason codes

The lifecycle surfaces at verification with distinct codes:
`CREDENTIAL_REVOKED` after a report, `HOLDER_MISMATCH` for the
stolen key against a replacement credential, `CREDENTIAL_EXPIRED`
for lapsed validity. Replays stay byte-identical; fresh nonces
prove the code, not the cache.

## Evidence

- `HolderDeviceCustodyTests` (6 tests): theft-to-reissue round
  trip with accept/reject reason codes, reissue-before-recovery
  refused, expiry death, atomic batch failure plus wrong-key
  proofs, idempotent reissue, device report negatives.
- `HolderCustodyFlowTests` / `HolderCustodyNegativeTests`: key
  custody unchanged (report refactor preserved behavior).
- `CrossReplicaConsentFlowTests`: the consent path survives
  replica split and restart, and peers re-validate proofs.
