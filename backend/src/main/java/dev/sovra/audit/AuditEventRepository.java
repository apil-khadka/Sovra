package dev.sovra.audit;

import dev.sovra.authz.ReasonCode;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/** Audit reads and writes on the tenant-scoped template (RLS applies). */
@Repository
public class AuditEventRepository {

  private final JdbcTemplate tenant;
  private final ObjectMapper mapper;

  public AuditEventRepository(
      @Qualifier("tenantJdbcTemplate") JdbcTemplate tenant, ObjectMapper mapper) {
    this.tenant = tenant;
    this.mapper = mapper;
  }

  public void insert(
      UUID tenantId,
      String actorType,
      String actorId,
      String action,
      String resourceType,
      String resourceId,
      String decision,
      ReasonCode reasonCode,
      long policyVersion,
      String correlationId,
      String detailJson) {
    tenant.update(
        "INSERT INTO audit_event (tenant_id, actor_type, actor_id, action,"
            + " resource_type, resource_id, decision, reason_code, policy_version,"
            + " correlation_id, detail)"
            + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb)",
        tenantId,
        actorType,
        actorId,
        action,
        resourceType,
        resourceId,
        decision,
        reasonCode.name(),
        policyVersion,
        correlationId,
        detailJson);
  }

  public List<Map<String, Object>> listRecent(UUID tenantId, int limit) {
    // Typed mapping: raw PG types (jsonb, arrays) must never reach Jackson.
    return tenant.query(
        "SELECT id, occurred_at, actor_type, actor_id, action, resource_type,"
            + " resource_id, decision, reason_code, policy_version, correlation_id, detail"
            + " FROM audit_event WHERE tenant_id = ? ORDER BY occurred_at DESC LIMIT ?",
        (rs, row) -> {
          Map<String, Object> event = new LinkedHashMap<>();
          event.put("id", rs.getString("id"));
          event.put("occurredAt", rs.getTimestamp("occurred_at").toInstant().toString());
          event.put("actorType", rs.getString("actor_type"));
          event.put("actorId", rs.getString("actor_id"));
          event.put("action", rs.getString("action"));
          event.put("resourceType", rs.getString("resource_type"));
          event.put("resourceId", rs.getString("resource_id"));
          event.put("decision", rs.getString("decision"));
          event.put("reasonCode", rs.getString("reason_code"));
          event.put("policyVersion", rs.getLong("policy_version"));
          event.put("correlationId", rs.getString("correlation_id"));
          event.put("detail", readTree(rs.getString("detail")));
          return event;
        },
        tenantId,
        Math.min(Math.max(limit, 1), 100));
  }

  private JsonNode readTree(String json) {
    try {
      return mapper.readTree(json);
    } catch (tools.jackson.core.JacksonException e) {
      throw new IllegalStateException("stored audit detail is not JSON", e);
    }
  }
}
