package dev.sovra.ops;

import java.util.Map;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Key availability: at least one registered issuer signing key must be
 * usable (registered and not revoked). Counts only; key material never
 * leaves the database.
 */
@Component
public class KeyAvailabilityCheck implements ReadinessCheck {

  private final JdbcTemplate global;

  public KeyAvailabilityCheck(DataSource globalDataSource) {
    this.global = new JdbcTemplate(globalDataSource);
  }

  @Override
  public String name() {
    return "key_availability";
  }

  @Override
  public CheckResult check() {
    long start = System.nanoTime();
    try {
      Integer usable =
          global.queryForObject(
              "SELECT COUNT(*) FROM issuer_signing_key k WHERE NOT EXISTS"
                  + " (SELECT 1 FROM issuer_key_revocation r WHERE r.issuer_id = k.issuer_id"
                  + " AND r.key_id = k.key_id AND r.key_version = k.key_version)",
              Integer.class);
      long durationMs = DatabaseCheck.elapsedMs(start);
      int count = usable == null ? 0 : usable;
      if (count > 0) {
        return CheckResult.up(name(), "keys_usable", Map.of("usableKeys", count), durationMs);
      }
      return CheckResult.down(name(), "no_usable_keys", Map.of("usableKeys", 0), durationMs);
    } catch (Exception e) {
      return CheckResult.down(name(), "unreachable", Map.of(), DatabaseCheck.elapsedMs(start));
    }
  }
}
