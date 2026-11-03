package dev.sovra.planning;

import java.time.Clock;
import java.time.LocalDate;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Fleet-wide live-AI budget ledger (PROD-012). Every live call
 * reserves requests, tokens, and a concurrency slot atomically —
 * one transaction holding the day-row lock — before touching the
 * provider, then settles with actual usage, refunds an unspent
 * reservation, or burns the estimate on uncertain outcomes.
 * Timeouts, crashes, and unknown provider states never refund:
 * the sweeper converts abandoned leases to UNCERTAIN past expiry.
 */
@Service
public class AiBudgetService {

  private static final Logger log = LoggerFactory.getLogger(AiBudgetService.class);

  private final JdbcTemplate global;
  private final TransactionTemplate transactions;
  private final Clock clock;
  private final AiBudgetProperties budgets;

  public AiBudgetService(
      DataSource globalDataSource, Clock clock, AiBudgetProperties budgets) {
    this.global = new JdbcTemplate(globalDataSource);
    // The ledger owns its transaction boundary on its own DataSource:
    // an injected manager bound to another pool would silently run
    // reservations outside any transaction and over-admit under race.
    this.transactions =
        new TransactionTemplate(new DataSourceTransactionManager(globalDataSource));
    this.clock = clock;
    this.budgets = budgets;
  }

  /** One metered provider call: reserve, invoke, settle-or-burn. */
  public interface AiCall<T> {

    T invoke() throws Exception;

    /** Provider-reported usage, or -1 when the provider omits it. */
    long usageOf(T result);
  }

  /**
   * A metered call that tops up its reservation as the session grows.
   * The lease id is injected after the initial reserve and before
   * {@link #invoke}, so each further outbound attempt can pre-fund its
   * own worst case through {@link #topUp} before any bytes leave.
   */
  public interface LeaseAwareCall<T> extends AiCall<T> {

    void lease(UUID leaseId);
  }

  /**
   * A pre-call abort: the guard refused another outbound attempt, so no
   * provider contact happened in the refused round. Carries the failure
   * the caller sees plus the spend to settle: exact accumulated usage
   * when every completed round reported it, else the funded reservation
   * (never burned, never hidden).
   */
  public static final class BudgetAbort extends RuntimeException {

    private final long knownActual;
    private final RuntimeException failure;

    public BudgetAbort(long knownActual, RuntimeException failure) {
      super(failure.getMessage(), failure);
      this.knownActual = knownActual;
      this.failure = failure;
    }

    long knownActual() {
      return knownActual;
    }

    RuntimeException failure() {
      return failure;
    }
  }

  /**
   * Runs a metered call. Success settles actual usage (or the
   * estimate when the provider omits usage); a pre-call abort settles
   * the exact accumulated spend of the completed rounds; any other
   * failure after the reservation burns the estimate as UNCERTAIN,
   * because a failed call may still have spent server-side.
   */
  public <T> T execute(UUID tenantId, long estimatedTokens, AiCall<T> call) throws Exception {
    UUID lease = reserve(tenantId, estimatedTokens);
    if (call instanceof LeaseAwareCall<T> aware) {
      aware.lease(lease);
    }
    try {
      T result = call.invoke();
      long actual = call.usageOf(result);
      // Unknown usage settles the live reservation — the topped-up
      // total for sessions that grew — never just the first bound.
      settle(lease, actual < 0 ? currentEstimate(lease) : actual);
      return result;
    } catch (BudgetAbort abort) {
      settle(lease, abort.knownActual());
      throw abort.failure();
    } catch (Exception e) {
      // Framework backstop: the tool loop may wrap a guard refusal
      // in its own exception type. A wrapped abort still means no
      // provider contact in the refused round, so it settles exact
      // completed spend instead of burning the funding.
      for (Throwable t = e; t != null; t = t.getCause()) {
        if (t instanceof BudgetAbort abort) {
          settle(lease, abort.knownActual());
          throw abort.failure();
        }
      }
      burnUncertain(lease);
      throw e;
    }
  }

  /**
   * Reserves one request, {@code estimatedTokens} tokens, and a
   * concurrency slot, or throws {@link AiBudgetExhaustedException}.
   * The caller must settle, refund, or abandon (sweeper burns) the
   * returned lease.
   */
  public UUID reserve(UUID tenantId, long estimatedTokens) {
    if (estimatedTokens <= 0) {
      throw new IllegalArgumentException("token estimate must be positive");
    }
    LocalDate today = LocalDate.now(clock);
    applyDailyLimitReductions(today);
    return transactions.execute(
        status -> {
          // Create the first row inside the reservation transaction.
          // If the first request is denied (for example, a zero budget),
          // rollback leaves no misleading daily ledger row behind.
          global.update(
              "INSERT INTO ai_budget_day (day, request_limit, token_limit, concurrency_limit)"
                  + " VALUES (?, ?, ?, ?) ON CONFLICT (day) DO NOTHING",
              today,
              budgets.dailyRequests(),
              budgets.dailyTokens(),
              budgets.maxConcurrency());
          // A concurrently inserted row can have come from a replica with
          // higher limits, so reduce it again while holding this transaction.
          global.update(
              "UPDATE ai_budget_day SET"
                  + " request_limit = LEAST(request_limit, ?),"
                  + " token_limit = LEAST(token_limit, ?),"
                  + " concurrency_limit = LEAST(concurrency_limit, ?)"
                  + " WHERE day = ?",
              budgets.dailyRequests(),
              budgets.dailyTokens(),
              budgets.maxConcurrency(),
              today);
          DayRow day =
              global.queryForObject(
                  "SELECT request_limit, token_limit, concurrency_limit,"
                      + " requests_used, tokens_used, requests_reserved, tokens_reserved"
                      + " FROM ai_budget_day WHERE day = ? FOR UPDATE",
                  (rs, row) ->
                      new DayRow(
                          rs.getInt(1),
                          rs.getLong(2),
                          rs.getInt(3),
                          rs.getInt(4),
                          rs.getLong(5),
                          rs.getInt(6),
                          rs.getLong(7)),
                  today);
          int held =
              global.queryForObject(
                  "SELECT COUNT(*) FROM ai_call_lease"
                      + " WHERE state = 'HELD' AND expires_at > now()",
                  Integer.class);
          if (day.requestsUsed() + day.requestsReserved() >= day.requestLimit()) {
            throw new AiBudgetExhaustedException("daily live-AI request budget exhausted");
          }
          if (day.tokensUsed() + day.tokensReserved() + estimatedTokens > day.tokenLimit()) {
            throw new AiBudgetExhaustedException("daily live-AI token budget exhausted");
          }
          if (held >= day.concurrencyLimit()) {
            throw new AiBudgetExhaustedException("live-AI fleet concurrency exhausted");
          }
          global.update(
              "UPDATE ai_budget_day SET requests_reserved = requests_reserved + 1,"
                  + " tokens_reserved = tokens_reserved + ? WHERE day = ?",
              estimatedTokens,
              today);
          return global.queryForObject(
              "INSERT INTO ai_call_lease (tenant_id, day, estimated_tokens, expires_at)"
                  + " VALUES (?, ?, ?, now() + (? || ' seconds')::interval) RETURNING id",
              UUID.class,
              tenantId,
              today,
              estimatedTokens,
              budgets.leaseSeconds());
        });
  }

  /**
   * Persist limit reductions before the reservation transaction can
   * reject and roll back. Limits only move downward within a UTC day;
   * increasing a cap requires the next daily row or an explicit
   * operator control plane, so one drifted replica cannot raise spend.
   */
  private void applyDailyLimitReductions(LocalDate day) {
    transactions.execute(
        status -> {
          global.update(
              "UPDATE ai_budget_day SET"
                  + " request_limit = LEAST(request_limit, ?),"
                  + " token_limit = LEAST(token_limit, ?),"
                  + " concurrency_limit = LEAST(concurrency_limit, ?)"
                  + " WHERE day = ?",
              budgets.dailyRequests(),
              budgets.dailyTokens(),
              budgets.maxConcurrency(),
              day);
          return null;
        });
  }

  /**
   * Grows a held lease's token reservation before another outbound
   * attempt, or throws {@link AiBudgetExhaustedException} when the
   * growth would pass the day's token limit (the caller aborts the
   * session without further provider contact). Zero growth only
   * heartbeats: every round renews the lease expiry, so a progressing
   * session never trips the sweeper while a stalled one still does.
   * Lock order matches {@link #reserve} (day row, then lease).
   */
  public void topUp(UUID leaseId, long additionalTokens) {
    if (additionalTokens < 0) {
      throw new IllegalArgumentException("top-up cannot be negative");
    }
    List<LocalDate> days =
        global.query(
            "SELECT day FROM ai_call_lease WHERE id = ?",
            (rs, n) -> rs.getObject(1, LocalDate.class),
            leaseId);
    if (days.isEmpty()) {
      throw new IllegalStateException("AI lease is not held: " + leaseId);
    }
    LocalDate day = days.get(0);
    transactions.execute(
        status -> {
          DayRow row =
              global.queryForObject(
                  "SELECT request_limit, token_limit, concurrency_limit,"
                      + " requests_used, tokens_used, requests_reserved, tokens_reserved"
                      + " FROM ai_budget_day WHERE day = ? FOR UPDATE",
                  (rs, n) ->
                      new DayRow(
                          rs.getInt(1),
                          rs.getLong(2),
                          rs.getInt(3),
                          rs.getInt(4),
                          rs.getLong(5),
                          rs.getInt(6),
                          rs.getLong(7)),
                  day);
          String state =
              global.queryForObject(
                  "SELECT state FROM ai_call_lease WHERE id = ? FOR UPDATE",
                  String.class,
                  leaseId);
          if (!"HELD".equals(state)) {
            throw new IllegalStateException("AI lease is not held: " + leaseId);
          }
          if (row.tokensUsed() + row.tokensReserved() + additionalTokens > row.tokenLimit()) {
            throw new AiBudgetExhaustedException("daily live-AI token budget exhausted");
          }
          global.update(
              "UPDATE ai_budget_day SET tokens_reserved = tokens_reserved + ? WHERE day = ?",
              additionalTokens,
              day);
          global.update(
              "UPDATE ai_call_lease SET estimated_tokens = estimated_tokens + ?,"
                  + " expires_at = now() + (? || ' seconds')::interval WHERE id = ?",
              additionalTokens,
              budgets.leaseSeconds(),
              leaseId);
          return null;
        });
  }

  /** Configured lease lifetime in seconds, for admission adequacy checks. */
  public int leaseSeconds() {
    return budgets.leaseSeconds();
  }

  /** Live reservation of a lease, grown by {@link #topUp}. */
  public long currentEstimate(UUID leaseId) {
    List<Long> estimates =
        global.query(
            "SELECT estimated_tokens FROM ai_call_lease WHERE id = ?",
            (rs, n) -> rs.getLong(1),
            leaseId);
    if (estimates.isEmpty()) {
      throw new IllegalStateException("AI lease is not held: " + leaseId);
    }
    return estimates.get(0);
  }

  /** Settles a held lease with actual provider usage. */
  public void settle(UUID leaseId, long actualTokens) {
    if (actualTokens < 0) {
      throw new IllegalArgumentException("settled usage cannot be negative");
    }
    int updated =
        transactions.execute(
            status ->
                global.update(
                    "WITH lease AS ("
                        + " UPDATE ai_call_lease SET state = 'SETTLED',"
                        + " settled_tokens = ?, settled_at = now()"
                        + " WHERE id = ? AND state = 'HELD' RETURNING day, estimated_tokens)"
                        + " UPDATE ai_budget_day SET"
                        + " requests_used = requests_used + 1,"
                        + " requests_reserved = requests_reserved - 1,"
                        + " tokens_used = tokens_used + ?,"
                        + " tokens_reserved = tokens_reserved - lease.estimated_tokens"
                        + " FROM lease WHERE ai_budget_day.day = lease.day",
                    actualTokens,
                    leaseId,
                    actualTokens));
    if (updated == 0) {
      throw new IllegalStateException("AI lease is not held: " + leaseId);
    }
    // Bound-violation signal: actual spend past the funded reservation
    // means a sizing assumption broke. Recorded honestly above, never
    // hidden — and always loud, so operators re-size before re-arming.
    long[] pair =
        global.queryForObject(
            "SELECT estimated_tokens, settled_tokens FROM ai_call_lease WHERE id = ?",
            (rs, n) -> new long[] {rs.getLong(1), rs.getLong(2)},
            leaseId);
    if (pair != null && pair[1] > pair[0]) {
      log.warn(
          "live-AI lease {} settled {} tokens past its {} reservation",
          leaseId,
          pair[1],
          pair[0]);
    }
  }

  /** Returns an unspent reservation (caller aborted before the provider call). */
  public void refund(UUID leaseId) {
    int updated =
        transactions.execute(
            status ->
                global.update(
                    "WITH lease AS ("
                        + " UPDATE ai_call_lease SET state = 'REFUNDED', settled_at = now()"
                        + " WHERE id = ? AND state = 'HELD' RETURNING day, estimated_tokens)"
                        + " UPDATE ai_budget_day SET"
                        + " requests_reserved = requests_reserved - 1,"
                        + " tokens_reserved = tokens_reserved - lease.estimated_tokens"
                        + " FROM lease WHERE ai_budget_day.day = lease.day",
                    leaseId));
    if (updated == 0) {
      throw new IllegalStateException("AI lease is not held: " + leaseId);
    }
  }

  /**
   * Burns a held lease as UNCERTAIN: the estimate counts as spent.
   * Scheduled sweeps call this path for abandoned leases, and
   * {@link #execute} for failed calls.
   */
  public void burnUncertain(UUID leaseId) {
    int updated =
        transactions.execute(
            status ->
                global.update(
                    "WITH lease AS ("
                        + " UPDATE ai_call_lease SET state = 'UNCERTAIN',"
                        + " settled_tokens = estimated_tokens, settled_at = now()"
                        + " WHERE id = ? AND state = 'HELD' RETURNING day, estimated_tokens)"
                        + " UPDATE ai_budget_day SET"
                        + " requests_used = requests_used + 1,"
                        + " requests_reserved = requests_reserved - 1,"
                        + " tokens_used = tokens_used + lease.estimated_tokens,"
                        + " tokens_reserved = tokens_reserved - lease.estimated_tokens"
                        + " FROM lease WHERE ai_budget_day.day = lease.day",
                    leaseId));
    if (updated == 0) {
      throw new IllegalStateException("AI lease is not held: " + leaseId);
    }
  }

  /** Sweeps abandoned leases past expiry into UNCERTAIN (conservative burn). */
  @Scheduled(fixedDelay = 60_000)
  public int sweepStale() {
    int count =
        transactions.execute(
            status -> {
              List<Burned> expired =
                  global.query(
                      "UPDATE ai_call_lease SET state = 'UNCERTAIN',"
                          + " settled_tokens = estimated_tokens, settled_at = now()"
                          + " WHERE state = 'HELD' AND expires_at <= now()"
                          + " RETURNING day, estimated_tokens",
                      (rs, row) ->
                          new Burned(
                              rs.getObject(1, LocalDate.class), rs.getLong(2)));
              for (Burned burn : expired) {
                global.update(
                    "UPDATE ai_budget_day SET requests_used = requests_used + 1,"
                        + " requests_reserved = requests_reserved - 1,"
                        + " tokens_used = tokens_used + ?,"
                        + " tokens_reserved = tokens_reserved - ? WHERE day = ?",
                    burn.tokens(),
                    burn.tokens(),
                    burn.day());
              }
              return expired.size();
            });
    if (count > 0) {
      log.warn("burned {} abandoned live-AI lease(s) as uncertain", count);
    }
    return count;
  }

  record DayRow(
      int requestLimit,
      long tokenLimit,
      int concurrencyLimit,
      int requestsUsed,
      long tokensUsed,
      int requestsReserved,
      long tokensReserved) {}

  record Burned(LocalDate day, long tokens) {}
}
