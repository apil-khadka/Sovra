package dev.sovra.sdk;

import java.util.Map;
import java.util.Optional;
import tools.jackson.databind.JsonNode;

/**
 * Presentation verification. One decision per nonce: resending the
 * same nonce replays the stored response byte-for-byte, while the
 * same nonce with different content conflicts without rewriting.
 */
public final class VerificationClient {

  private final SovraClient client;

  VerificationClient(SovraClient client) {
    this.client = client;
  }

  public record Decision(
      String decisionId,
      String requestId,
      String outcome,
      String reasonCode,
      boolean synthetic,
      String profile,
      long trustSnapshot,
      String keyRef,
      long statusVersion,
      String decidedAt) {}

  public Decision verify(
      String requestId, String nonce, String audience, JsonNode holderJwk, String bindingProof) {
    return client.post(
        "/api/verification/presentations",
        Map.of("requestId", requestId, "nonce", nonce, "audience", audience,
            "holderJwk", holderJwk, "bindingProof", bindingProof),
        Decision.class);
  }

  public Decision get(String decisionId) {
    return get(decisionId, null).orElseThrow(() -> new SovraApiError(
        304, "not_modified", "server answered 304 without a precondition", false));
  }

  /** Empty on 304 when the caller holds the current decision. */
  public Optional<Decision> get(String decisionId, String ifNoneMatch) {
    return client.get(
        "/api/verification/decisions/" + decisionId, ifNoneMatch, Decision.class);
  }
}
