package dev.sovra.ops;

import java.util.Map;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/** Liveness of the database dependency itself: connect plus SELECT 1. */
@Component
public class DatabaseCheck implements ReadinessCheck {

  private final JdbcTemplate global;

  public DatabaseCheck(DataSource globalDataSource) {
    this.global = new JdbcTemplate(globalDataSource);
  }

  @Override
  public String name() {
    return "database";
  }

  @Override
  public CheckResult check() {
    long start = System.nanoTime();
    try {
      Integer one = global.queryForObject("SELECT 1", Integer.class);
      long durationMs = elapsedMs(start);
      if (one != null && one == 1) {
        return CheckResult.up(name(), "reachable", Map.of(), durationMs);
      }
      return CheckResult.down(name(), "unexpected_result", Map.of(), durationMs);
    } catch (Exception e) {
      return CheckResult.down(name(), "unreachable", Map.of(), elapsedMs(start));
    }
  }

  static long elapsedMs(long startNanos) {
    return Math.max(0, (System.nanoTime() - startNanos) / 1_000_000);
  }
}
