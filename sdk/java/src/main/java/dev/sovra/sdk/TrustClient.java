package dev.sovra.sdk;

import java.util.List;
import java.util.Map;
import tools.jackson.databind.JsonNode;

/** Trust review queue and key lifecycle (TRUST_ADMIN). */
public final class TrustClient {

  private final SovraClient client;

  TrustClient(SovraClient client) {
    this.client = client;
  }

  public record ProposalSummary(
      String proposalId,
      long version,
      String state,
      String proposedBy,
      String approvedBy,
      String createdAt) {}

  public record ProposeResult(String version, String proposalId) {}

  public record ApproveResult(String proposalId, String personVerified) {}

  public record ActivateResult(String version) {}

  public record KeyView(
      String issuerId, String keyId, int keyVersion, String status, String revokedAt) {}

  public List<ProposalSummary> proposals() {
    return client.get("/api/trust/proposals", ProposalList.class);
  }

  public ProposeResult propose(
      List<Map<String, Object>> issuers, List<Map<String, Object>> policies, String note) {
    return client.post(
        "/api/trust/proposals",
        Map.of("issuers", issuers, "policies", policies, "note", note == null ? "" : note),
        ProposeResult.class);
  }

  public ApproveResult approve(String proposalId) {
    return client.post(
        "/api/trust/proposals/" + proposalId + "/approve", Map.of(), ApproveResult.class);
  }

  public ActivateResult activate(long version) {
    return client.post("/api/trust/snapshots/" + version + "/activate", Map.of(),
        ActivateResult.class);
  }

  public KeyView registerKey(
      String issuerId, String keyId, int keyVersion, JsonNode publicKeyJwk) {
    return client.post(
        "/api/trust/keys",
        Map.of("issuerId", issuerId, "keyId", keyId, "keyVersion", keyVersion,
            "publicKeyJwk", publicKeyJwk),
        KeyView.class);
  }

  public KeyView revokeKey(String issuerId, String keyId, int keyVersion, String reason) {
    return client.post(
        "/api/trust/keys/revoke",
        Map.of("issuerId", issuerId, "keyId", keyId, "keyVersion", keyVersion, "reason", reason),
        KeyView.class);
  }

  public static final class ProposalList extends java.util.ArrayList<ProposalSummary> {}
}
