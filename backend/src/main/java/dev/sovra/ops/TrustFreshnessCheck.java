package dev.sovra.ops;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Authority freshness (SOV-029): the flow may only accept evidence under a
 * live trust snapshot. Queries the activation row and the active snapshot's
 * issuer validity windows directly — never a cached flag — so stale or
 * missing authority closes readiness even while HTTP probes succeed.
 */
@Component
public class TrustFreshnessCheck implements ReadinessCheck {

  private final JdbcTemplate global;
  private final Clock clock;

  public TrustFreshnessCheck(DataSource globalDataSource, Clock clock) {
    this.global = new JdbcTemplate(globalDataSource);
    this.clock = clock;
  }

  @Override
  public String name() {
    return "trust_freshness";
  }

  @Override
  public CheckResult check() {
    long start = System.nanoTime();
    try {
      Long version =
          global.queryForObject(
              "SELECT MAX(snapshot_version) FROM trust_snapshot_activation", Long.class);
      if (version == null) {
        return CheckResult.down(
            name(), "no_active_snapshot", Map.of(), DatabaseCheck.elapsedMs(start));
      }
      List<IssuerWindow> windows =
          global.query(
              "SELECT status, valid_from, valid_through FROM issuer_record"
                  + " WHERE snapshot_version = ?",
              (rs, row) ->
                  new IssuerWindow(
                      rs.getString("status"),
                      rs.getTimestamp("valid_from").toInstant(),
                      rs.getTimestamp("valid_through").toInstant()),
              version);
      return evaluate(name(), version, windows, clock.instant(), DatabaseCheck.elapsedMs(start));
    } catch (Exception e) {
      return CheckResult.down(name(), "unreachable", Map.of(), DatabaseCheck.elapsedMs(start));
    }
  }

  record IssuerWindow(String status, Instant validFrom, Instant validThrough) {}

  /**
   * Pure evaluation over the live-fetched windows, so stale, expired, and
   * empty authority states are unit-testable without a database.
   */
  static CheckResult evaluate(
      String name, long version, List<IssuerWindow> windows, Instant now, long durationMs) {
    long usable =
        windows.stream()
            .filter(w -> "ACTIVE".equals(w.status()))
            .filter(w -> !w.validFrom().isAfter(now) && !w.validThrough().isBefore(now))
            .count();
    Map<String, Object> detail = Map.of("snapshotVersion", version, "usableIssuers", usable);
    if (usable > 0) {
      return CheckResult.up(name, "authority_live", detail, durationMs);
    }
    return CheckResult.down(name, "stale_authority", detail, durationMs);
  }
}
