package dev.sovra.ops;

import dev.sovra.authz.EmergencyFlagService;
import java.util.Map;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Authorization/key dependency: the policy version query and the live
 * emergency flag must both be readable. An engaged freeze is fail-closed
 * and healthy, but no flow can proceed, so readiness closes as DEGRADED
 * rather than UP.
 */
@Component
public class AuthorizationCheck implements ReadinessCheck {

  private final JdbcTemplate global;
  private final EmergencyFlagService emergency;

  public AuthorizationCheck(DataSource globalDataSource, EmergencyFlagService emergency) {
    this.global = new JdbcTemplate(globalDataSource);
    this.emergency = emergency;
  }

  @Override
  public String name() {
    return "authorization";
  }

  @Override
  public CheckResult check() {
    long start = System.nanoTime();
    try {
      Long active =
          global.queryForObject(
              "SELECT COALESCE(MAX(snapshot_version), 0) FROM trust_snapshot_activation",
              Long.class);
      boolean frozen = emergency.enabled();
      long durationMs = DatabaseCheck.elapsedMs(start);
      Map<String, Object> detail =
          Map.of("policyEpoch", active == null ? 0L : active, "frozen", frozen);
      if (frozen) {
        return CheckResult.degraded(name(), "emergency_freeze", detail, durationMs);
      }
      return CheckResult.up(name(), "policy_readable", detail, durationMs);
    } catch (Exception e) {
      return CheckResult.down(name(), "unreachable", Map.of(), DatabaseCheck.elapsedMs(start));
    }
  }
}
