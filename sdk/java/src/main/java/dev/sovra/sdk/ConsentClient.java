package dev.sovra.sdk;

import java.util.Map;
import java.util.Optional;
import tools.jackson.databind.JsonNode;

/** Consent-bound proof requests: RP creation, holder review/decision, presentation reads. */
public final class ConsentClient {

  private final SovraClient client;

  ConsentClient(SovraClient client) {
    this.client = client;
  }

  public record RequestView(
      String requestId,
      String rpId,
      String audience,
      String purpose,
      String credentialId,
      Map<String, Object> claims,
      String planHash,
      String challenge,
      String holderThumbprint,
      String state,
      String stateReason,
      String createdAt,
      String expiresAt,
      long trustSnapshot) {}

  public record PresentationView(
      String requestId,
      String state,
      boolean synthetic,
      String profile,
      String presentation,
      Map<String, Object> claims,
      String expiresAt,
      long trustSnapshot) {}

  public RequestView create(
      String rpId,
      String audience,
      String purpose,
      String credentialId,
      Map<String, Object> claims,
      Map<String, Object> plan,
      String policyId,
      String policyVersion,
      String planHash,
      String challenge,
      String expiresAt) {
    Map<String, Object> body = new java.util.HashMap<>();
    body.put("rpId", rpId);
    body.put("audience", audience);
    body.put("purpose", purpose);
    body.put("credentialId", credentialId);
    body.put("claims", claims);
    body.put("plan", plan);
    body.put("policyId", policyId);
    body.put("policyVersion", policyVersion);
    body.put("planHash", planHash);
    body.put("challenge", challenge);
    body.put("expiresAt", expiresAt);
    return client.post("/api/consent/requests", body, RequestView.class);
  }

  public RequestView review(String requestId) {
    return review(requestId, null).orElseThrow(() -> new SovraApiError(
        304, "not_modified", "server answered 304 without a precondition", false));
  }

  /** Empty on 304 when the caller holds the current review. */
  public Optional<RequestView> review(String requestId, String ifNoneMatch) {
    return client.get("/api/consent/requests/" + requestId, ifNoneMatch, RequestView.class);
  }

  public RequestView decide(
      String requestId, String decision, JsonNode holderJwk, String consentProof) {
    return client.post(
        "/api/consent/requests/" + requestId + "/decision",
        Map.of("decision", decision, "holderJwk", holderJwk, "consentProof", consentProof),
        RequestView.class);
  }

  public PresentationView presentation(String requestId) {
    return client.get(
        "/api/consent/requests/" + requestId + "/presentation", PresentationView.class);
  }
}
