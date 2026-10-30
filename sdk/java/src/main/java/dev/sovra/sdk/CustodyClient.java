package dev.sovra.sdk;

import java.util.Map;
import java.util.Optional;
import tools.jackson.databind.JsonNode;

/**
 * Holder key custody: loss reports end a key's authority at once;
 * recovery activates a fresh proven key. Reads stay metadata-only.
 */
public final class CustodyClient {

  private final SovraClient client;

  CustodyClient(SovraClient client) {
    this.client = client;
  }

  public record Reported(
      String keyId, String recoveryId, String thumbprint, int revokedCredentials) {}

  public record Recovered(String recoveryId, String newThumbprint) {}

  public record RecoveryView(
      String recoveryId, String reason, String state, String newThumbprint) {}

  public record KeyView(
      String keyId,
      String enrollmentId,
      String thumbprint,
      String status,
      String createdBy,
      java.util.List<RecoveryView> recoveries) {}

  public Reported report(String thumbprint, String reason) {
    return client.post(
        "/api/holder-keys/report", Map.of("thumbprint", thumbprint, "reason", reason),
        Reported.class);
  }

  public Recovered recover(String recoveryId, JsonNode newHolderJwk, String newKeyProof) {
    Map<String, Object> body = new java.util.HashMap<>();
    body.put("recoveryId", recoveryId);
    body.put("newHolderJwk", newHolderJwk);
    if (newKeyProof != null) {
      body.put("newKeyProof", newKeyProof);
    }
    return client.post("/api/holder-keys/recover", body, Recovered.class);
  }

  public KeyView get(String keyId) {
    return get(keyId, null).orElseThrow(() -> new SovraApiError(
        304, "not_modified", "server answered 304 without a precondition", false));
  }

  /** Empty on 304 when the caller holds the current key view. */
  public Optional<KeyView> get(String keyId, String ifNoneMatch) {
    return client.get("/api/holder-keys/" + keyId, ifNoneMatch, KeyView.class);
  }
}
