package dev.sovra.ops;

import java.util.List;
import javax.sql.DataSource;
import org.springframework.stereotype.Component;

/**
 * Durable-audit dependency: audit rows commit atomically with business
 * writes, so a broken audit path must close readiness. Proves the INSERT
 * path with a rollback-only probe; persists nothing.
 */
@Component
public class AuditDurabilityCheck implements ReadinessCheck {

  private final DataSource dataSource;

  public AuditDurabilityCheck(DataSource globalDataSource) {
    this.dataSource = globalDataSource;
  }

  @Override
  public String name() {
    return "audit_durability";
  }

  @Override
  public CheckResult check() {
    return RollbackProbe.probe(
        name(),
        dataSource,
        "INSERT INTO audit_event (tenant_id, actor_type, actor_id, action, resource_type,"
            + " resource_id, decision, reason_code, policy_version, correlation_id, detail)"
            + " VALUES (?, 'probe', 'readiness', 'PROBE', 'probe', '', 'PERMIT', 'PERMIT', 0,"
            + " '', '{}'::jsonb)",
        List.of());
  }
}
