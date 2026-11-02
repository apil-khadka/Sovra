package dev.sovra.admission;

import java.util.List;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/**
 * Fleet-wide token buckets over PostgreSQL (PROD-006). Refill and
 * consume happen in one conditional {@code UPDATE}, so concurrent
 * consumers on any number of replicas share one exact balance with
 * no distributed lock. The database clock arbitrates refill, so
 * replica clock skew cannot grant extra tokens.
 *
 * <p>Uses the plain datasource: buckets are keyed by authenticated
 * ids or coarse anonymous scopes, never by tenant row policy.
 */
@Repository
public class JdbcRateLimiter {

  public record Verdict(boolean allowed, long retryAfterSeconds) {}

  private final JdbcTemplate jdbc;

  public JdbcRateLimiter(DataSource globalDataSource) {
    this.jdbc = new JdbcTemplate(globalDataSource);
  }

  /**
   * Consumes {@code cost} tokens from {@code bucket}. An absent
   * bucket starts full. Denials carry a retry delay derived from
   * the same refill math, so callers never guess.
   */
  public Verdict consume(String bucket, double capacity, double ratePerSecond, double cost) {
    for (int attempt = 0; attempt < 2; attempt++) {
      List<Double> remaining =
          jdbc.query(
              "UPDATE rate_limit_bucket"
                  + " SET tokens = LEAST(?::float8,"
                  + " tokens + ?::float8 * EXTRACT(EPOCH FROM (now() - updated_at))) - ?::float8,"
                  + " updated_at = now()"
                  + " WHERE bucket = ?"
                  + " AND LEAST(?::float8,"
                  + " tokens + ?::float8 * EXTRACT(EPOCH FROM (now() - updated_at))) >= ?::float8"
                  + " RETURNING tokens",
              (rs, row) -> rs.getDouble("tokens"),
              capacity,
              ratePerSecond,
              cost,
              bucket,
              capacity,
              ratePerSecond,
              cost);
      if (remaining.size() == 1) {
        return new Verdict(true, 0);
      }
      if (bucketExists(bucket)) {
        return new Verdict(false, retryAfterSeconds(bucket, capacity, ratePerSecond, cost));
      }
      insertFull(bucket, capacity);
    }
    // The insert raced another replica's insert: the bucket exists
    // now, so the denial below rechecks against live state.
    return new Verdict(false, retryAfterSeconds(bucket, capacity, ratePerSecond, cost));
  }

  private boolean bucketExists(String bucket) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM rate_limit_bucket WHERE bucket = ?", Integer.class, bucket);
    return count != null && count > 0;
  }

  private void insertFull(String bucket, double capacity) {
    jdbc.update(
        "INSERT INTO rate_limit_bucket (bucket, tokens, updated_at)"
            + " VALUES (?, ?, now()) ON CONFLICT (bucket) DO NOTHING",
        bucket,
        capacity);
  }

  private long retryAfterSeconds(String bucket, double capacity, double ratePerSecond, double cost) {
    Double available =
        jdbc.queryForObject(
            "SELECT LEAST(?::float8,"
                + " tokens + ?::float8 * EXTRACT(EPOCH FROM (now() - updated_at)))"
                + " FROM rate_limit_bucket WHERE bucket = ?",
            Double.class,
            capacity,
            ratePerSecond,
            bucket);
    double missing = cost - (available == null ? 0.0 : available);
    if (missing <= 0 || ratePerSecond <= 0) {
      return 1;
    }
    return Math.max(1, (long) Math.ceil(missing / ratePerSecond));
  }

  /**
   * Reaps buckets idle since {@code idleSince}. Idle buckets
   * recreate full. PROD-010: bounded batch; a backlog drains over
   * successive nightly runs instead of one long lock.
   */
  public int deleteIdle(java.time.Instant idleSince) {
    return jdbc.update(
        "DELETE FROM rate_limit_bucket WHERE bucket IN ("
            + " SELECT bucket FROM rate_limit_bucket"
            + " WHERE updated_at < ? ORDER BY updated_at LIMIT 1000)",
        java.sql.Timestamp.from(idleSince));
  }
}
