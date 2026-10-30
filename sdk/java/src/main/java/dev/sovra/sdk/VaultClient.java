package dev.sovra.sdk;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Encrypted vault: purpose-bound storage with grants. Uploads are
 * bounded server-side; reads need a live grant for the exact
 * purpose and workload.
 */
public final class VaultClient {

  private final SovraClient client;

  VaultClient(SovraClient client) {
    this.client = client;
  }

  public record StoredVersion(String objectId, int version) {}

  public record VersionMetadata(
      int version,
      List<String> purposes,
      int kekVersion,
      String status,
      String contentSha256Hex,
      String createdAt) {}

  public record ObjectMetadata(
      String objectId, String issuerId, String displayName, List<VersionMetadata> versions) {}

  public record GrantView(
      String grantId,
      String objectId,
      int objectVersion,
      String principalType,
      String principalId,
      String purpose,
      String workload,
      boolean revoked,
      String expiresAt,
      String createdAt) {}

  public record ReadView(
      String objectId, int version, String contentSha256Hex, String contentBase64) {}

  public record KekVersion(int kekVersion) {}

  public record DeletedVersion(String objectId, int version, String status) {}

  public StoredVersion store(
      String issuerId, String displayName, List<String> purposes, byte[] content) {
    Map<String, Object> body = new HashMap<>();
    body.put("issuerId", issuerId);
    body.put("displayName", displayName == null ? "" : displayName);
    body.put("purposes", purposes);
    body.put("contentBase64",
        java.util.Base64.getEncoder().encodeToString(content == null ? new byte[0] : content));
    return client.post("/api/vault/objects", body, StoredVersion.class);
  }

  public StoredVersion storeVersion(String objectId, List<String> purposes, byte[] content) {
    return client.post(
        "/api/vault/objects/" + objectId + "/versions",
        Map.of("purposes", purposes, "contentBase64",
            java.util.Base64.getEncoder().encodeToString(content == null ? new byte[0] : content)),
        StoredVersion.class);
  }

  public ObjectMetadata metadata(String objectId) {
    return client.get("/api/vault/objects/" + objectId, ObjectMetadata.class);
  }

  public ReadView read(
      String objectId, int version, String grantId, String purpose, String workload) {
    return client.post(
        "/api/vault/objects/" + objectId + "/versions/" + version + "/read",
        Map.of("grantId", grantId, "purpose", purpose, "workload", workload), ReadView.class);
  }

  public GrantView grant(
      String objectId,
      int objectVersion,
      String principalType,
      String principalId,
      String purpose,
      String workload,
      long ttlSeconds) {
    Map<String, Object> body = new HashMap<>();
    body.put("objectId", objectId);
    body.put("objectVersion", objectVersion);
    if (principalType != null) {
      body.put("principalType", principalType);
    }
    if (principalId != null) {
      body.put("principalId", principalId);
    }
    body.put("purpose", purpose);
    body.put("workload", workload);
    body.put("ttlSeconds", ttlSeconds);
    return client.post("/api/vault/grants", body, GrantView.class);
  }

  public GrantView revokeGrant(String grantId) {
    return client.post("/api/vault/grants/" + grantId + "/revoke", Map.of(), GrantView.class);
  }

  public KekVersion rotateKek() {
    return client.post("/api/vault/keys/rotate", Map.of(), KekVersion.class);
  }

  public DeletedVersion deleteVersion(String objectId, int version) {
    return client.post(
        "/api/vault/objects/" + objectId + "/versions/" + version + "/delete", Map.of(),
        DeletedVersion.class);
  }
}
