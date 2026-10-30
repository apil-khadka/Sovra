package dev.sovra.sdk;

import java.util.HashMap;
import java.util.Map;
import tools.jackson.databind.JsonNode;

/**
 * Issuer-scoped credential issuance. The idempotency key makes
 * retries safe: resending the same key and request replays the
 * original response byte-for-byte instead of minting twice.
 */
public final class IssuanceClient {

  private final SovraClient client;

  IssuanceClient(SovraClient client) {
    this.client = client;
  }

  public record IssuedCredential(
      String credentialId, String artifact, String status, String expiresAt, long trustSnapshot) {}

  public record CredentialView(
      String credentialId,
      String issuerId,
      String vct,
      String keyRef,
      String issuedAt,
      String expiresAt,
      String status,
      long trustSnapshot) {}

  public record StatusView(String status, long version, String fetchedAt, long maxAgeSeconds) {}

  public IssuedCredential issue(
      String idempotencyKey,
      String issuerId,
      String vct,
      JsonNode holderJwk,
      String holderProof,
      Map<String, Object> claims,
      String expiresAt,
      String enrollmentId) {
    if (!Idempotency.valid(idempotencyKey)) {
      throw new IllegalArgumentException("idempotency key is malformed");
    }
    Map<String, Object> body = new HashMap<>();
    body.put("issuerId", issuerId);
    body.put("vct", vct);
    body.put("holderJwk", holderJwk);
    body.put("holderProof", holderProof);
    body.put("claims", claims);
    body.put("expiresAt", expiresAt);
    if (enrollmentId != null) {
      body.put("enrollmentId", enrollmentId);
    }
    return client.post(
        "/api/issuance/credentials", body, Map.of("Idempotency-Key", idempotencyKey),
        IssuedCredential.class);
  }

  public CredentialView get(String credentialId) {
    return client.get("/api/issuance/credentials/" + credentialId, CredentialView.class);
  }

  public StatusView status(String credentialId) {
    return client.get(
        "/api/issuance/credentials/" + credentialId + "/status", StatusView.class);
  }

  public record Revoked(String credentialId, String status) {}

  public Revoked revoke(String credentialId) {
    return client.post(
        "/api/issuance/credentials/" + credentialId + "/revoke", Map.of(), Revoked.class);
  }

  public String jwks() {
    return client.get("/api/issuance/jwks.json", String.class);
  }
}
