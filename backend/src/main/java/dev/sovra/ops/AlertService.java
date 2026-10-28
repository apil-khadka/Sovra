package dev.sovra.ops;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Service;

/**
 * Security alerts derived from semantic readiness (SOV-029). Every non-UP
 * check raises an alert — including unsafe stale authority and audit-commit
 * failure while HTTP liveness probes succeed — so operators page on flow
 * safety, not just process survival. State is per-instance and
 * crash-explicit: {@code firstObservedAt} tracks continuous observation by
 * this instance, and a restart honestly restarts the clock.
 */
@Service
public class AlertService {

  static final Map<String, AlertSpec> ALERTS =
      Map.of(
          "database", new AlertSpec("DATABASE_UNREACHABLE", "critical"),
          "migrations", new AlertSpec("SCHEMA_INCOMPLETE", "critical"),
          "trust_freshness", new AlertSpec("STALE_TRUST_AUTHORITY", "high"),
          "authorization", new AlertSpec("AUTHORIZATION_DEGRADED", "critical"),
          "audit_durability", new AlertSpec("AUDIT_COMMIT_FAILURE", "critical"),
          "replay_persistence", new AlertSpec("REPLAY_STORE_DEGRADED", "high"),
          "key_availability", new AlertSpec("KEYS_UNAVAILABLE", "high"));

  private final FlowReadinessService readiness;
  private final Clock clock;
  private final ConcurrentHashMap<String, Instant> firstObserved = new ConcurrentHashMap<>();

  public AlertService(FlowReadinessService readiness, Clock clock) {
    this.readiness = readiness;
    this.clock = clock;
  }

  /** Active alerts now; recovered checks clear, and their clocks reset. */
  public List<Alert> active() {
    FlowReadinessService.ReadinessReport report = readiness.report();
    Instant now = clock.instant();
    List<Alert> firing = new ArrayList<>();
    for (CheckResult result : report.checks()) {
      if (result.status() == CheckStatus.UP) {
        firstObserved.remove(result.name());
        continue;
      }
      AlertSpec spec = ALERTS.getOrDefault(result.name(), new AlertSpec("CHECK_DEGRADED", "medium"));
      Instant first = firstObserved.computeIfAbsent(result.name(), k -> now);
      firing.add(
          new Alert(
              spec.name(),
              spec.severity(),
              result.status().name(),
              result.code(),
              result.name(),
              first,
              now));
    }
    // A check that vanished from the report (misconfiguration) must not
    // linger as a stale clock.
    firstObserved.keySet().retainAll(firing.stream().map(Alert::check).toList());
    return List.copyOf(firing);
  }

  record AlertSpec(String name, String severity) {}

  public record Alert(
      String alert,
      String severity,
      String status,
      String code,
      String check,
      Instant firstObservedAt,
      Instant observedAt) {}
}
