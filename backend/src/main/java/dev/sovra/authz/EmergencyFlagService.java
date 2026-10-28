package dev.sovra.authz;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Live emergency flag (SOV-004: 5-second TTL). When enabled, every
 * authorization decision denies. Only the database owner can flip the
 * flag, which is the documented break-glass path.
 */
@Service
public class EmergencyFlagService {

  static final Duration TTL = Duration.ofSeconds(5);

  private final JdbcTemplate global;
  private final Clock clock;
  private volatile Instant validUntil = Instant.MIN;
  private volatile boolean cached;

  public EmergencyFlagService(DataSource globalDataSource, Clock clock) {
    this.global = new JdbcTemplate(globalDataSource);
    this.clock = clock;
  }

  public synchronized boolean enabled() {
    Instant now = clock.instant();
    if (now.isBefore(validUntil)) {
      return cached;
    }
    cached =
        Boolean.TRUE.equals(
            global.queryForObject(
                "SELECT enabled FROM emergency_flag WHERE id = 1", Boolean.class));
    validUntil = now.plus(TTL);
    return cached;
  }

  /** Test hook; production code never calls this. */
  synchronized void clearCache() {
    validUntil = Instant.MIN;
  }
}
