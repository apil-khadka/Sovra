package dev.sovra.issuance;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Validated issuance evidence: the only input the credential encoder
 * accepts. The service assembles this after trust, scope, holder-proof,
 * and authorization checks; the encoder re-validates the claim allowlist
 * before anything is signed.
 */
public record IssuanceEvidence(
    UUID credentialId,
    String issuerId,
    KeyRef keyRef,
    String vct,
    Map<String, Object> claims,
    String holderThumbprint,
    Instant issuedAt,
    Instant expiresAt,
    long trustSnapshotVersion,
    String statusUri) {}
