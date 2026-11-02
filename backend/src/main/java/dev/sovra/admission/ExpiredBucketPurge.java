package dev.sovra.admission;

import java.time.Clock;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Reaps rate-limit buckets idle over a day (PROD-006/PROD-010).
 * Idle buckets recreate full on next use, so the reap only bounds
 * table growth; idempotent across replicas.
 */
@Component
public class ExpiredBucketPurge {

  private static final Logger log = LoggerFactory.getLogger(ExpiredBucketPurge.class);

  private final JdbcRateLimiter limiter;
  private final Clock clock;

  public ExpiredBucketPurge(JdbcRateLimiter limiter, Clock clock) {
    this.limiter = limiter;
    this.clock = clock;
  }

  @Scheduled(cron = "0 0 3 * * *")
  public void purge() {
    int removed = limiter.deleteIdle(clock.instant().minus(Duration.ofDays(1)));
    if (removed > 0) {
      log.info("reaped {} idle rate-limit buckets", removed);
    }
  }
}
