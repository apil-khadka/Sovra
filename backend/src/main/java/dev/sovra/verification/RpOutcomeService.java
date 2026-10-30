package dev.sovra.verification;

import dev.sovra.audit.AuditService;
import dev.sovra.audit.AuditedAuthorizer;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ResourceRef;
import dev.sovra.authz.Role;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * RP-dashboard verification reads (SOV-025): recent outcomes
 * and safe usage metrics. Outcome rows carry the decision id,
 * request, outcome, and reason — never the decision bytes, so
 * no claim content crosses this path. Pure relying parties
 * see only decisions their own credential submitted (the
 * server-set {@code decided_by}, not the self-asserted
 * {@code rp_id} label); tenant members see the tenant's,
 * holding the audience boundary below the agent line
 * without a separate endpoint.
 */
@Service
public class RpOutcomeService {

  static final Set<Role> AGENT_ROLES =
      Set.of(Role.TENANT_MEMBER, Role.AUDIT_READER, Role.TRUST_ADMIN);

  public record OutcomeView(
      UUID decisionId,
      UUID requestId,
      String rpId,
      String outcome,
      String reasonCode,
      Instant decidedAt) {}

  public record MetricsView(long total, long accepted, long rejected, long unknown) {}

  private final AuthorizationService authz;
  private final AuditService audit;
  private final JdbcTemplate tenant;

  public RpOutcomeService(
      AuthorizationService authz, AuditService audit, JdbcTemplate tenantJdbcTemplate) {
    this.authz = authz;
    this.audit = audit;
    this.tenant = tenantJdbcTemplate;
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public List<OutcomeView> outcomes(ServiceAccountPrincipal caller, int limit) {
    ResourceRef resource =
        ResourceRef.tenantScoped("rp-outcome", "list", caller.tenantId());
    Decision decision =
        AuditedAuthorizer.require(authz, audit, caller, Action.READ_RP_REQUESTS, resource);
    int bounded = Math.min(100, Math.max(1, limit));
    boolean agent = caller.roles().stream().anyMatch(AGENT_ROLES::contains);
    List<OutcomeView> items =
        agent
            ? tenant.query(
                "SELECT id, request_id, rp_id, outcome, reason_code, decided_at"
                    + " FROM verification_decision WHERE tenant_id = ?"
                    + " ORDER BY decided_at DESC, id DESC LIMIT ?",
                this::mapRow, caller.tenantId(), bounded)
            : tenant.query(
                "SELECT id, request_id, rp_id, outcome, reason_code, decided_at"
                    + " FROM verification_decision WHERE tenant_id = ? AND decided_by = ?"
                    + " ORDER BY decided_at DESC, id DESC LIMIT ?",
                this::mapRow, caller.tenantId(), caller.name(), bounded);
    audit.record(caller, Action.READ_RP_REQUESTS, resource, decision, "",
        Map.of("count", String.valueOf(items.size()), "scoped", String.valueOf(!agent)));
    return items;
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public MetricsView metrics(ServiceAccountPrincipal caller) {
    ResourceRef resource =
        ResourceRef.tenantScoped("rp-outcome", "metrics", caller.tenantId());
    Decision decision =
        AuditedAuthorizer.require(authz, audit, caller, Action.READ_RP_METRICS, resource);
    boolean agent = caller.roles().stream().anyMatch(AGENT_ROLES::contains);
    String sql = "SELECT outcome, COUNT(*) FROM verification_decision"
        + " WHERE tenant_id = ?" + (agent ? "" : " AND decided_by = ?") + " GROUP BY outcome";
    Map<String, Long> counts = new java.util.HashMap<>();
    if (agent) {
      tenant.query(sql, (rs, row) -> counts.put(rs.getString(1), rs.getLong(2)),
          caller.tenantId());
    } else {
      tenant.query(sql, (rs, row) -> counts.put(rs.getString(1), rs.getLong(2)),
          caller.tenantId(), caller.name());
    }
    long accepted = counts.getOrDefault("ACCEPTED", 0L);
    long rejected = counts.getOrDefault("REJECTED", 0L);
    long unknown = counts.getOrDefault("UNKNOWN", 0L);
    audit.record(caller, Action.READ_RP_METRICS, resource, decision, "",
        Map.of("scoped", String.valueOf(!agent)));
    return new MetricsView(accepted + rejected + unknown, accepted, rejected, unknown);
  }

  private OutcomeView mapRow(java.sql.ResultSet rs, int row) throws java.sql.SQLException {
    return new OutcomeView(
        rs.getObject("id", UUID.class),
        rs.getObject("request_id", UUID.class),
        rs.getString("rp_id"),
        rs.getString("outcome"),
        rs.getString("reason_code"),
        rs.getTimestamp("decided_at").toInstant());
  }
}
