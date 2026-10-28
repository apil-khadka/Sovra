package dev.sovra.guard;

import java.time.Instant;
import java.util.List;

/**
 * Issuer trust metadata pinned for one epoch. Standing (status plus
 * validity window) is checked against the explicit guard clock; scope
 * (credential types, attestable claims) bounds what a plan may ask of
 * the issuer.
 */
public record TrustedIssuer(
    String issuerId,
    List<String> allowedCredentialTypes,
    List<String> allowedClaims,
    List<String> keyIds,
    String status,
    Instant validFrom,
    Instant validThrough) {}
