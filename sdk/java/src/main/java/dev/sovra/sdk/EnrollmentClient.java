package dev.sovra.sdk;

import java.util.Map;
import java.util.Optional;
import tools.jackson.databind.JsonNode;

/**
 * Enrollment review with maker/checker separation. Approvals pin
 * the current extraction head; eligibility answers the issuance
 * gate with reviewed claims only.
 */
public final class EnrollmentClient {

  private final SovraClient client;

  EnrollmentClient(SovraClient client) {
    this.client = client;
  }

  public record Created(String enrollmentId, String subjectRef, String state) {}

  public record StateView(String enrollmentId, String state) {}

  public record DecisionView(String enrollmentId, String state, int boundRevision) {}

  public record EligibilityView(
      String enrollmentId, boolean eligible, String reason, Map<String, String> claims) {}

  public record ReviewView(
      int revision, String decision, boolean bindingProofOk, String reviewer) {}

  public record EnrollmentView(
      String enrollmentId,
      String subjectRef,
      String vaultObjectId,
      String extractionRecordId,
      int boundRevision,
      String state,
      String createdBy,
      String decidedBy,
      boolean eligible,
      String eligibilityReason,
      java.util.List<ReviewView> reviews) {}

  public Created create(String vaultObjectId, String extractionRecordId, JsonNode holderJwk) {
    return client.post(
        "/api/enrollments",
        Map.of("vaultObjectId", vaultObjectId, "extractionRecordId", extractionRecordId,
            "holderJwk", holderJwk),
        Created.class);
  }

  public StateView submit(String enrollmentId) {
    return client.post(
        "/api/enrollments/" + enrollmentId + "/submit", Map.of(), StateView.class);
  }

  public DecisionView decide(
      String enrollmentId, int revision, String decision, String bindingProof) {
    Map<String, Object> body = new java.util.HashMap<>();
    body.put("revision", revision);
    body.put("decision", decision);
    if (bindingProof != null) {
      body.put("bindingProof", bindingProof);
    }
    return client.post(
        "/api/enrollments/" + enrollmentId + "/decision", body, DecisionView.class);
  }

  public EnrollmentView get(String enrollmentId) {
    return get(enrollmentId, null).orElseThrow(() -> new SovraApiError(
        304, "not_modified", "server answered 304 without a precondition", false));
  }

  /** Empty on 304 when the caller holds the current case. */
  public Optional<EnrollmentView> get(String enrollmentId, String ifNoneMatch) {
    return client.get("/api/enrollments/" + enrollmentId, ifNoneMatch, EnrollmentView.class);
  }

  public EligibilityView eligibility(String enrollmentId) {
    return client.get(
        "/api/enrollments/" + enrollmentId + "/eligibility", EligibilityView.class);
  }
}
