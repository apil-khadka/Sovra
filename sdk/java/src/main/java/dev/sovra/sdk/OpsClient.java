package dev.sovra.sdk;

import java.util.List;
import java.util.Map;
import tools.jackson.databind.JsonNode;

/** Operational reads: health, readiness, trust snapshot, audit, alerts, identity. */
public final class OpsClient {

  private final SovraClient client;

  OpsClient(SovraClient client) {
    this.client = client;
  }

  public record Health(String status, String service, String version) {}

  public record ReadinessCheck(
      String name, String status, String code, Map<String, Object> detail, long durationMs) {}

  public record ReadinessReport(String status, List<ReadinessCheck> checks) {}

  public record SnapshotIssuer(
      String issuerId,
      String displayName,
      String scope,
      List<String> credentialTypes,
      String keyId,
      int keyVersion,
      JsonNode publicKeyJwk,
      String validFrom,
      String validThrough,
      String status) {}

  public record SnapshotPolicy(
      String rpId, String purpose, List<String> allowedTypes, String maxAssurance) {}

  public record TrustSnapshot(long version, List<SnapshotIssuer> issuers, List<SnapshotPolicy> policies) {}

  public record WhoAmI(String accountId, String tenantId, String name, List<String> roles) {}

  public record AuditEvent(
      String id,
      String occurredAt,
      String actorType,
      String actorId,
      String action,
      String resourceType,
      String resourceId,
      String decision,
      String reasonCode,
      long policyVersion,
      String correlationId,
      JsonNode detail) {}

  public record Alert(
      String alert,
      String severity,
      String status,
      String code,
      String check,
      String firstObservedAt,
      String observedAt) {}

  public Health health() {
    return client.get("/api/health", Health.class);
  }

  public ReadinessReport readiness() {
    return client.get("/api/health/ready", ReadinessReport.class);
  }

  /** Active federation snapshot, or null when none is activated yet. */
  public TrustSnapshot snapshot() {
    try {
      return client.get("/api/trust/snapshots/current", TrustSnapshot.class);
    } catch (SovraApiError e) {
      if (e.status() == 404) {
        return null;
      }
      throw e;
    }
  }

  public WhoAmI whoami() {
    return client.get("/api/whoami", WhoAmI.class);
  }

  /** Newest audit rows first; the cursor passes through opaquely. */
  public List<AuditEvent> audit(int limit, String cursor) {
    String path = "/api/audit/events?limit=" + limit
        + (cursor == null ? "" : "&cursor=" + Url.encode(cursor));
    return client.get(path, AuditEventList.class);
  }

  /** Builds the next-page cursor from the last row of a page. */
  public static String cursorFor(AuditEvent last) {
    String raw = last.occurredAt() + "|" + last.id();
    return java.util.Base64.getUrlEncoder().withoutPadding()
        .encodeToString(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }

  public List<Alert> alerts() {
    return client.get("/api/alerts", AlertList.class);
  }

  /** Jackson-friendly list wrapper; callers see plain lists. */
  public static final class AuditEventList extends java.util.ArrayList<AuditEvent> {}

  public static final class AlertList extends java.util.ArrayList<Alert> {}
}
