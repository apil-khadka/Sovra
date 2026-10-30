package dev.sovra.sdk;

import java.util.Map;

/** Hostile-image quarantine: sealed admission, isolated verdicts, clean promotion. */
public final class QuarantineClient {

  private final SovraClient client;

  QuarantineClient(SovraClient client) {
    this.client = client;
  }

  public record Admitted(
      String admissionId, String objectId, String status, String actualType, int sizeBytes) {}

  public record AdmissionView(
      String admissionId,
      String objectId,
      String status,
      String claimedType,
      String actualType,
      int sizeBytes,
      String contentSha256Hex,
      String verdict,
      Integer imageWidth,
      Integer imageHeight,
      String scannedAt,
      String createdAt) {}

  public record Promoted(String admissionId, String objectId, int version) {}

  public Admitted admit(byte[] content, String claimedType, String issuerId) {
    return client.post(
        "/api/quarantine/admissions",
        Map.of("contentBase64",
            java.util.Base64.getEncoder().encodeToString(content == null ? new byte[0] : content),
            "claimedType", claimedType, "issuerId", issuerId),
        Admitted.class);
  }

  /** Metadata-only: no endpoint serves quarantine bytes. */
  public AdmissionView get(String admissionId) {
    return client.get("/api/quarantine/admissions/" + admissionId, AdmissionView.class);
  }

  public Promoted promote(
      String admissionId,
      String grantId,
      String purpose,
      String workload,
      java.util.List<String> purposes,
      String displayName) {
    Map<String, Object> body = new java.util.HashMap<>();
    body.put("grantId", grantId);
    body.put("purpose", purpose);
    body.put("workload", workload);
    if (purposes != null) {
      body.put("purposes", purposes);
    }
    if (displayName != null) {
      body.put("displayName", displayName);
    }
    return client.post(
        "/api/quarantine/admissions/" + admissionId + "/promote", body, Promoted.class);
  }
}
