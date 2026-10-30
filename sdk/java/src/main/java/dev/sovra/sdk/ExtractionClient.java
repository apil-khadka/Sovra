package dev.sovra.sdk;

import java.util.Map;
import java.util.Optional;

/**
 * Local extraction runs with protected digests and provenance.
 * Digests are integrity references inside authorized reads; no
 * call resolves rows by digest.
 */
public final class ExtractionClient {

  private final SovraClient client;

  ExtractionClient(SovraClient client) {
    this.client = client;
  }

  public record RunResult(String recordId, int revision, String sourceDigestHex) {}

  public record CorrectionResult(String recordId, int revision) {}

  public record ApprovalResult(String recordId, int approvedRevision) {}

  public record RecordSummary(
      String recordId,
      String vaultObjectId,
      int objectVersion,
      String engineId,
      String schemaId,
      Integer approvedRevision,
      int latestRevision,
      String createdBy,
      String createdAt) {}

  public record RecordPage(java.util.List<RecordSummary> items, String nextCursor) {}

  public record RevisionView(
      int revNo,
      Map<String, String> observed,
      Map<String, String> normalized,
      Map<String, String> canonicalDigests,
      Map<String, String> exactDigests,
      double confidence,
      Integer supersedes,
      String createdBy) {}

  public record RecordView(
      String recordId,
      String vaultObjectId,
      int objectVersion,
      String sourceDigestHex,
      String engineId,
      String schemaId,
      String normalizerId,
      String canonId,
      Integer approvedRevision,
      java.util.List<RevisionView> revisions) {}

  public RunResult run(
      String vaultObjectId,
      int objectVersion,
      String grantId,
      String purpose,
      String workload,
      String schemaId) {
    return client.post(
        "/api/extraction/records",
        Map.of("vaultObjectId", vaultObjectId, "objectVersion", objectVersion, "grantId",
            grantId, "purpose", purpose, "workload", workload, "schemaId", schemaId),
        RunResult.class);
  }

  public RecordView get(String recordId) {
    return get(recordId, null).orElseThrow(() -> new SovraApiError(
        304, "not_modified", "server answered 304 without a precondition", false));
  }

  /** Empty on 304 when the caller holds the current record. */
  public Optional<RecordView> get(String recordId, String ifNoneMatch) {
    return client.get("/api/extraction/records/" + recordId, ifNoneMatch, RecordView.class);
  }

  /** Review queue: state in all/pending/stale/approved, keyset-paged. */
  public RecordPage list(String state, int limit, String cursor) {
    StringBuilder path = new StringBuilder("/api/extraction/records?limit=" + limit);
    if (state != null) {
      path.append("&state=").append(Url.encode(state));
    }
    if (cursor != null) {
      path.append("&cursor=").append(Url.encode(cursor));
    }
    return client.get(path.toString(), RecordPage.class);
  }

  public CorrectionResult correct(
      String recordId, Map<String, String> fields, double confidence) {
    return client.post(
        "/api/extraction/records/" + recordId + "/revisions",
        Map.of("fields", fields, "confidence", confidence), CorrectionResult.class);
  }

  public ApprovalResult approve(String recordId, int revision) {
    return client.post(
        "/api/extraction/records/" + recordId + "/approval", Map.of("revision", revision),
        ApprovalResult.class);
  }
}
