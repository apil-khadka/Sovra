package dev.sovra.trust;

import tools.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * SOV-001 profile validation for trust proposals. Structural checks only;
 * cryptographic verification of key bindings happens in SOV-011 against
 * live issuer metadata.
 */
public final class TrustProposalValidator {

  static final String VCT_PREFIX = "https://sovra.example/vct/";
  static final Set<String> ASSURANCE_LEVELS = Set.of("LOW", "MEDIUM", "HIGH");

  private TrustProposalValidator() {}

  public static void validate(TrustService.ProposalInput input, Instant now) {
    if (input.issuers().isEmpty() && input.policies().isEmpty()) {
      throw new InvalidProposalException("proposal must carry issuers or policies");
    }
    for (TrustService.IssuerInput issuer : input.issuers()) {
      requireText(issuer.issuerId(), "issuer_id");
      requireText(issuer.scope(), "scope");
      if (issuer.credentialTypes().isEmpty()) {
        throw new InvalidProposalException("issuer needs credential types");
      }
      for (String vct : issuer.credentialTypes()) {
        if (vct == null || !vct.startsWith(VCT_PREFIX)) {
          throw new InvalidProposalException("unapproved credential type: " + vct);
        }
      }
      validateKey(issuer.keyId(), issuer.publicKeyJwk());
      if (issuer.keyVersion() < 1) {
        throw new InvalidProposalException("key version starts at 1");
      }
      if (issuer.validFrom() == null
          || issuer.validThrough() == null
          || !issuer.validFrom().isBefore(issuer.validThrough())) {
        throw new InvalidProposalException("key validity window is empty");
      }
      if (!issuer.validThrough().isAfter(now)) {
        throw new InvalidProposalException("key already expired");
      }
      if (!Set.of(IssuerStatus.ACTIVE.name(), IssuerStatus.SUSPENDED.name())
          .contains(issuer.status())) {
        throw new InvalidProposalException("new keys must be ACTIVE or SUSPENDED");
      }
    }
    for (TrustService.PolicyInput policy : input.policies()) {
      requireText(policy.rpId(), "rp_id");
      requireText(policy.purpose(), "purpose");
      if (policy.allowedTypes().isEmpty()) {
        throw new InvalidProposalException("policy needs allowed types");
      }
      for (String vct : policy.allowedTypes()) {
        if (vct == null || !vct.startsWith(VCT_PREFIX)) {
          throw new InvalidProposalException("unapproved policy type: " + vct);
        }
      }
      if (!ASSURANCE_LEVELS.contains(policy.maxAssurance())) {
        throw new InvalidProposalException("unknown assurance level");
      }
    }
  }

  /** ES256 (P-256) JWK shape with kid bound to the key record. */
  static void validateKey(String keyId, JsonNode jwk) {
    if (jwk == null || !jwk.isObject()) {
      throw new InvalidProposalException("key must be a JWK object");
    }
    requireField(jwk, "kty", "EC");
    requireField(jwk, "crv", "P-256");
    if (!jwk.hasNonNull("x") || !jwk.hasNonNull("y")) {
      throw new InvalidProposalException("JWK needs x and y coordinates");
    }
    if (!jwk.hasNonNull("kid") || !keyId.equals(jwk.get("kid").asText())) {
      throw new InvalidProposalException("JWK kid must equal the key record id");
    }
    if (jwk.has("d")) {
      throw new InvalidProposalException("private key material is never accepted");
    }
  }

  private static void requireField(JsonNode jwk, String field, String expected) {
    if (!jwk.hasNonNull(field) || !expected.equals(jwk.get(field).asText())) {
      throw new InvalidProposalException("JWK needs " + field + "=" + expected);
    }
  }

  private static void requireText(String value, String field) {
    if (value == null || value.isBlank()) {
      throw new InvalidProposalException(field + " is required");
    }
  }
}
