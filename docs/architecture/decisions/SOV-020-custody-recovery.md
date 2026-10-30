# SOV-020: demo holder custody and recovery (OD-09)

**Version:** 0.1.
**Date:** 2026-10-30.
**Task:** [SOV-020](https://github.com/apil-khadka/Sovra/issues/25)
(holder credential custody and secure recovery).

This record freezes OD-09 for the synthetic demo: who owns holder
keys, what the server stores, and how loss, theft, and compromise
are handled. Production device custody, hardware attestation, and
MFA-backed administration stay open (section 5).

## 1. Ownership

Holder private keys live on holder devices only. The browser demo
wallet keeps keys in React memory and discards them on reset or
view exit. The server never receives, stores, or backs up private
key material: the `holder_key` registry holds public JWKs, and a
SQL CHECK rejects any JWK carrying private fields.

## 2. Registration

Approving an enrollment activates its holder key: the decision
inserts the ACTIVE registry row for the case key. Rejected cases
register nothing. The demo binds one holder key to one
enrollment: approving a second case on an already-registered key
conflicts, so a key can never silently authorize two subjects.
Moving a key means recovery, not sharing.

## 3. Loss, theft, and compromise

Any issuer operator may report a key: the report flips the key to
COMPROMISED, opens a recovery case, and revokes every credential
bound to the key's thumbprint at once. Compromised keys stay in
the registry as history; revocation, not deletion, ends their
authority, so presentations of recovered credentials keep
failing through the existing revocation checks.

## 4. Recovery

Recovery is a high-impact action and requires TRUST_ADMIN. It
requires all three: the enrollment is still currently eligible
(re-proof of the live case, not of the lost key), a possession
proof from the fresh replacement key over the recovery id, and
an administrator identity. Recovery activates the new key,
closes the case with the replacement link, and leaves reissuance
to the normal issuance flow — recovered credentials are never
resurrected; new credential ids are minted under the
profile-compliant issuance path.

## 5. What stays open for production

This freeze covers the demo only. Before live credentials: real
device key custody (secure enclave/strongbox with attestation),
an approved encrypted-backup design, MFA plus step-up
reauthorization for report/recovery (SR-02), holder-facing
recovery UX with an approved accessibility target (OD-12), and
independent review (SOV-037).
