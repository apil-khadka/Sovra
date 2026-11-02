package dev.sovra.admission;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraPostgresBase;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Fleet-wide token buckets in SQL (PROD-006): refill math, burst
 * caps, exact concurrent consumption, honest retry delays, and idle
 * reaping. Runs as the least-privilege role to prove the migration
 * grants.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class JdbcRateLimiterTests extends SovraPostgresBase {

  JdbcRateLimiter limiter;
  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    limiter = new JdbcRateLimiter(appRoleDataSource());
    owner = new JdbcTemplate(ownerDataSource());
    owner.update("DELETE FROM rate_limit_bucket");
  }

  @Test
  void absentBucketsStartFullThenRefillOverTime() {
    assertThat(limiter.consume("new-bucket", 3, 100, 1.0).allowed()).isTrue();
    assertThat(limiter.consume("new-bucket", 3, 100, 1.0).allowed()).isTrue();
    assertThat(limiter.consume("new-bucket", 3, 100, 1.0).allowed()).isTrue();
    // Spent: the fourth immediate consume is denied...
    JdbcRateLimiter.Verdict denied = limiter.consume("new-bucket", 3, 100, 1.0);
    assertThat(denied.allowed()).isFalse();
    assertThat(denied.retryAfterSeconds()).isGreaterThanOrEqualTo(1);
    // ... but 100 tokens/second refills the bucket almost at once.
    boolean recovered = false;
    for (int i = 0; i < 50 && !recovered; i++) {
      recovered = limiter.consume("new-bucket", 3, 100, 1.0).allowed();
      if (!recovered) {
        try {
          Thread.sleep(20);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }
    }
    assertThat(recovered).isTrue();
  }

  @Test
  void idleBucketsNeverExceedCapacity() throws Exception {
    // 100/s refills to the cap during the sleep, but negligibly
    // between back-to-back consumes.
    assertThat(limiter.consume("capped", 2, 100, 1.0).allowed()).isTrue();
    Thread.sleep(50);
    // Long idle: balance is capped at 2, so exactly two consumes fit.
    assertThat(limiter.consume("capped", 2, 100, 1.0).allowed()).isTrue();
    assertThat(limiter.consume("capped", 2, 100, 1.0).allowed()).isTrue();
    assertThat(limiter.consume("capped", 2, 100, 1.0).allowed()).isFalse();
  }

  @Test
  void concurrentConsumersShareOneExactBalance() throws Exception {
    int racers = 16;
    ExecutorService pool = Executors.newFixedThreadPool(racers);
    try {
      List<Future<Boolean>> futures = new ArrayList<>();
      for (int i = 0; i < racers; i++) {
        Callable<Boolean> race = () -> limiter.consume("race", 8, 0.01, 1.0).allowed();
        futures.add(pool.submit(race));
      }
      int allowed = 0;
      for (Future<Boolean> future : futures) {
        if (future.get()) {
          allowed++;
        }
      }
      // Eight tokens, sixteen racers, negligible refill: exactly
      // eight wins, decided by the single conditional UPDATE.
      assertThat(allowed).isEqualTo(8);
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  void retryDelayReflectsTheRefillRate() {
    limiter.consume("slow", 1, 0.5, 1.0);
    JdbcRateLimiter.Verdict denied = limiter.consume("slow", 1, 0.5, 1.0);
    assertThat(denied.allowed()).isFalse();
    // One missing token at half a token per second: two seconds.
    assertThat(denied.retryAfterSeconds()).isGreaterThanOrEqualTo(2);
  }

  @Test
  void idleBucketsReapCleanly() {
    limiter.consume("stale", 5, 1, 1.0);
    limiter.consume("fresh", 5, 1, 1.0);
    owner.update(
        "UPDATE rate_limit_bucket SET updated_at = now() - interval '2 days' WHERE bucket = 'stale'");
    assertThat(limiter.deleteIdle(java.time.Instant.now().minusSeconds(3600))).isEqualTo(1);
    assertThat(countRows()).isEqualTo(1);
  }

  private int countRows() {
    Integer count = owner.queryForObject("SELECT COUNT(*) FROM rate_limit_bucket", Integer.class);
    return count == null ? 0 : count;
  }
}
