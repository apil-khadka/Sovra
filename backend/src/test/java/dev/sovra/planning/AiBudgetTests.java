package dev.sovra.planning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraPostgresBase;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Fleet AI budget ledger (PROD-012): atomic reservations across
 * racers, exact settle/refund/burn accounting, concurrency caps,
 * and sweeper burns for abandoned leases — all as the
 * least-privilege role, no provider touched.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AiBudgetTests extends SovraPostgresBase {

  JdbcTemplate owner;
  JdbcTemplate app;

  @BeforeEach
  void setup() {
    owner = new JdbcTemplate(ownerDataSource());
    app = new JdbcTemplate(appRoleDataSource());
    owner.update("DELETE FROM ai_call_lease");
    owner.update("DELETE FROM ai_budget_day");
  }

  @Test
  void reserveSettleAccountsExactly() {
    AiBudgetService ledger = ledger(100, 1_000_000, 10);
    UUID lease = ledger.reserve(UUID.randomUUID(), 5_000);
    ledger.settle(lease, 3_000);
    assertThat(day().requestsUsed()).isEqualTo(1);
    assertThat(day().tokensUsed()).isEqualTo(3_000);
    assertThat(day().requestsReserved()).isEqualTo(0);
    assertThat(day().tokensReserved()).isEqualTo(0);
    assertThat(leaseState(lease)).isEqualTo("SETTLED");
  }

  @Test
  void refundReturnsReservation() {
    AiBudgetService ledger = ledger(100, 1_000_000, 10);
    UUID lease = ledger.reserve(UUID.randomUUID(), 5_000);
    ledger.refund(lease);
    assertThat(day().requestsUsed()).isEqualTo(0);
    assertThat(day().tokensUsed()).isEqualTo(0);
    assertThat(day().requestsReserved()).isEqualTo(0);
    assertThat(day().tokensReserved()).isEqualTo(0);
    assertThat(leaseState(lease)).isEqualTo("REFUNDED");
  }

  @Test
  void failureBurnsUncertain() {
    AiBudgetService ledger = ledger(100, 1_000_000, 10);
    UUID tenant = UUID.randomUUID();
    assertThatThrownBy(
            () -> ledger.execute(
                tenant,
                4_000,
                new AiBudgetService.AiCall<String>() {
                  @Override
                  public String invoke() {
                    throw new RuntimeException("provider timeout");
                  }

                  @Override
                  public long usageOf(String result) {
                    return -1;
                  }
                }))
        .isInstanceOf(RuntimeException.class)
        .hasMessageContaining("provider timeout");
    assertThat(day().requestsUsed()).isEqualTo(1);
    assertThat(day().tokensUsed()).isEqualTo(4_000);
    assertThat(day().requestsReserved()).isEqualTo(0);
    assertThat(
            owner.queryForObject(
                "SELECT state FROM ai_call_lease WHERE tenant_id = ?", String.class, tenant))
        .isEqualTo("UNCERTAIN");
  }

  @Test
  void successSettlesActualOrEstimate() throws Exception {
    AiBudgetService ledger = ledger(100, 1_000_000, 10);
    String ok =
        ledger.execute(
            UUID.randomUUID(),
            4_000,
            new AiBudgetService.AiCall<String>() {
              @Override
              public String invoke() {
                return "candidate";
              }

              @Override
              public long usageOf(String result) {
                return 2_500;
              }
            });
    assertThat(ok).isEqualTo("candidate");
    // Provider omits usage: settle the estimate, conservatively.
    ledger.execute(
        UUID.randomUUID(),
        4_000,
        new AiBudgetService.AiCall<String>() {
          @Override
          public String invoke() {
            return "candidate";
          }

          @Override
          public long usageOf(String result) {
            return -1;
          }
        });
    assertThat(day().requestsUsed()).isEqualTo(2);
    assertThat(day().tokensUsed()).isEqualTo(6_500);
  }

  @Test
  void quotaRaceAdmitsExactlyBudget() throws Exception {
    AiBudgetService ledger = ledger(5, 100_000_000L, 100);
    AtomicInteger admitted = new AtomicInteger();
    AtomicInteger denied = new AtomicInteger();
    ExecutorService pool = Executors.newFixedThreadPool(16);
    try {
      List<Future<?>> futures = new ArrayList<>();
      for (int i = 0; i < 16; i++) {
        futures.add(
            pool.submit(
                () -> {
                  try {
                    ledger.reserve(UUID.randomUUID(), 1_000);
                    admitted.incrementAndGet();
                  } catch (AiBudgetExhaustedException e) {
                    denied.incrementAndGet();
                  }
                }));
      }
      for (Future<?> future : futures) {
        future.get();
      }
    } finally {
      pool.shutdownNow();
    }
    assertThat(admitted.get()).isEqualTo(5);
    assertThat(denied.get()).isEqualTo(11);
    assertThat(day().requestsReserved()).isEqualTo(5);
  }

  @Test
  void concurrencyCapDeniesAndFrees() {
    AiBudgetService ledger = ledger(100, 1_000_000, 2);
    UUID first = ledger.reserve(UUID.randomUUID(), 1_000);
    ledger.reserve(UUID.randomUUID(), 1_000);
    assertThatThrownBy(() -> ledger.reserve(UUID.randomUUID(), 1_000))
        .isInstanceOf(AiBudgetExhaustedException.class)
        .hasMessageContaining("concurrency");
    ledger.settle(first, 1_000);
    ledger.reserve(UUID.randomUUID(), 1_000);
  }

  @Test
  void tokenBudgetDenies() {
    AiBudgetService ledger = ledger(100, 10_000, 10);
    ledger.reserve(UUID.randomUUID(), 6_000);
    assertThatThrownBy(() -> ledger.reserve(UUID.randomUUID(), 6_000))
        .isInstanceOf(AiBudgetExhaustedException.class)
        .hasMessageContaining("token budget");
  }

  @Test
  void runtimeLimitReductionTakesEffectWithoutAllowingAReplicaToRaiseTheCap() {
    AiBudgetProperties budgets = new AiBudgetProperties();
    budgets.setDailyRequests(10);
    budgets.setDailyTokens(10_000);
    budgets.setMaxConcurrency(10);
    budgets.setLeaseSeconds(3_600);
    AiBudgetService ledger = new AiBudgetService(
        appRoleDataSource(), Clock.systemUTC(), budgets);
    ledger.reserve(UUID.randomUUID(), 1_000);

    budgets.setDailyRequests(1);
    budgets.setDailyTokens(2_000);
    budgets.setMaxConcurrency(1);
    assertThatThrownBy(() -> ledger.reserve(UUID.randomUUID(), 1_000))
        .isInstanceOf(AiBudgetExhaustedException.class)
        .hasMessageContaining("request budget");

    budgets.setDailyRequests(100);
    budgets.setDailyTokens(1_000_000);
    budgets.setMaxConcurrency(100);
    assertThatThrownBy(() -> ledger.reserve(UUID.randomUUID(), 1_000))
        .isInstanceOf(AiBudgetExhaustedException.class)
        .hasMessageContaining("request budget");
    assertThat(owner.queryForObject(
        "SELECT request_limit FROM ai_budget_day WHERE day = CURRENT_DATE", Integer.class))
        .isEqualTo(1);
  }

  @Test
  void sweepBurnsAbandonedAndFreesTheSlot() {
    AiBudgetService ledger = ledger(100, 1_000_000, 1);
    UUID abandoned = ledger.reserve(UUID.randomUUID(), 7_000);
    // Simulate the kill-mid-call: the lease expires unsettled.
    owner.update(
        "UPDATE ai_call_lease SET expires_at = now() - interval '1 minute' WHERE id = ?",
        abandoned);
    assertThat(ledger.sweepStale()).isEqualTo(1);
    assertThat(leaseState(abandoned)).isEqualTo("UNCERTAIN");
    assertThat(day().tokensUsed()).isEqualTo(7_000);
    assertThat(day().tokensReserved()).isEqualTo(0);
    // The slot is free again, but the tokens stay burned.
    ledger.reserve(UUID.randomUUID(), 1_000);
    assertThat(day().tokensUsed()).isEqualTo(7_000);
  }

  @Test
  void doubleSettleFailsLoud() {
    AiBudgetService ledger = ledger(100, 1_000_000, 10);
    UUID lease = ledger.reserve(UUID.randomUUID(), 1_000);
    ledger.settle(lease, 1_000);
    assertThatThrownBy(() -> ledger.settle(lease, 1_000))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("not held");
  }

  @Test
  void topUpGrowsReservationAndSettlesActual() {
    AiBudgetService ledger = ledger(100, 1_000_000, 10);
    UUID lease = ledger.reserve(UUID.randomUUID(), 1_000);
    ledger.topUp(lease, 2_000);
    assertThat(ledger.currentEstimate(lease)).isEqualTo(3_000);
    assertThat(day().tokensReserved()).isEqualTo(3_000);
    ledger.settle(lease, 2_500);
    assertThat(day().tokensUsed()).isEqualTo(2_500);
    assertThat(day().tokensReserved()).isEqualTo(0);
    assertThat(leaseState(lease)).isEqualTo("SETTLED");
  }

  @Test
  void topUpPastLimitDeniedKeepsReservation() {
    AiBudgetService ledger = ledger(100, 10_000, 10);
    UUID lease = ledger.reserve(UUID.randomUUID(), 6_000);
    assertThatThrownBy(() -> ledger.topUp(lease, 5_000))
        .isInstanceOf(AiBudgetExhaustedException.class)
        .hasMessageContaining("token budget");
    assertThat(day().tokensReserved()).isEqualTo(6_000);
    assertThat(leaseState(lease)).isEqualTo("HELD");
    ledger.refund(lease);
  }

  @Test
  void topUpOnTerminalLeaseFailsLoud() {
    AiBudgetService ledger = ledger(100, 1_000_000, 10);
    UUID lease = ledger.reserve(UUID.randomUUID(), 1_000);
    ledger.settle(lease, 1_000);
    assertThatThrownBy(() -> ledger.topUp(lease, 1_000))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("not held");
    assertThatThrownBy(() -> ledger.topUp(UUID.randomUUID(), 1_000))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("not held");
  }

  @Test
  void topUpHeartbeatsPastSweep() {
    AiBudgetService ledger = ledger(100, 1_000_000, 10);
    UUID progressing = ledger.reserve(UUID.randomUUID(), 1_000);
    // The round took longer than the lease: a zero top-up renews the
    // expiry, so the sweeper leaves the progressing session alone.
    owner.update(
        "UPDATE ai_call_lease SET expires_at = now() - interval '1 minute' WHERE id = ?",
        progressing);
    ledger.topUp(progressing, 0);
    assertThat(ledger.sweepStale()).isZero();
    assertThat(leaseState(progressing)).isEqualTo("HELD");
    assertThat(day().tokensReserved()).isEqualTo(1_000);
    ledger.refund(progressing);
  }

  @Test
  void topUpRaceAdmitsExactlyRemaining() throws Exception {
    AiBudgetService ledger = ledger(100, 3_000, 10);
    UUID lease = ledger.reserve(UUID.randomUUID(), 1_000);
    AtomicInteger admitted = new AtomicInteger();
    AtomicInteger denied = new AtomicInteger();
    ExecutorService pool = Executors.newFixedThreadPool(8);
    try {
      List<Future<?>> futures = new ArrayList<>();
      for (int i = 0; i < 8; i++) {
        futures.add(
            pool.submit(
                () -> {
                  try {
                    ledger.topUp(lease, 1_500);
                    admitted.incrementAndGet();
                  } catch (AiBudgetExhaustedException e) {
                    denied.incrementAndGet();
                  }
                }));
      }
      for (Future<?> future : futures) {
        future.get();
      }
    } finally {
      pool.shutdownNow();
    }
    assertThat(admitted.get()).isEqualTo(1);
    assertThat(denied.get()).isEqualTo(7);
    assertThat(day().tokensReserved()).isEqualTo(2_500);
    ledger.refund(lease);
  }

  @Test
  void abortSettlesExactSpend() {
    AiBudgetService ledger = ledger(100, 1_000_000, 10);
    UUID tenant = UUID.randomUUID();
    assertThatThrownBy(
            () -> ledger.execute(
                tenant,
                4_000,
                new AiBudgetService.LeaseAwareCall<String>() {
                  @Override
                  public void lease(UUID leaseId) {}

                  @Override
                  public String invoke() {
                    throw new AiBudgetService.BudgetAbort(
                        1_200, new PlanningUnavailableException("budget exhausted"));
                  }

                  @Override
                  public long usageOf(String result) {
                    return -1;
                  }
                }))
        .isInstanceOf(PlanningUnavailableException.class)
        .hasMessageContaining("budget exhausted");
    assertThat(day().requestsUsed()).isEqualTo(1);
    assertThat(day().tokensUsed()).isEqualTo(1_200);
    assertThat(day().tokensReserved()).isZero();
    assertThat(
            owner.queryForObject(
                "SELECT state FROM ai_call_lease WHERE tenant_id = ?", String.class, tenant))
        .isEqualTo("SETTLED");
  }

  @Test
  void wrappedAbortStillSettlesExactSpend() {
    // The tool loop may wrap a guard refusal in a framework
    // exception; the ledger sees through the wrapper and settles
    // exact completed spend instead of burning the funding.
    AiBudgetService ledger = ledger(100, 1_000_000, 10);
    UUID tenant = UUID.randomUUID();
    assertThatThrownBy(
            () -> ledger.execute(
                tenant,
                4_000,
                new AiBudgetService.AiCall<String>() {
                  @Override
                  public String invoke() {
                    throw new RuntimeException(
                        "framework wrapper",
                        new AiBudgetService.BudgetAbort(
                            1_200, new PlanningUnavailableException("round budget exceeded")));
                  }

                  @Override
                  public long usageOf(String result) {
                    return -1;
                  }
                }))
        .isInstanceOf(PlanningUnavailableException.class)
        .hasMessageContaining("round budget");
    assertThat(day().requestsUsed()).isEqualTo(1);
    assertThat(day().tokensUsed()).isEqualTo(1_200);
    assertThat(day().tokensReserved()).isZero();
    assertThat(
            owner.queryForObject(
                "SELECT state FROM ai_call_lease WHERE tenant_id = ?", String.class, tenant))
        .isEqualTo("SETTLED");
  }

  @Test
  void unknownUsageSettlesLiveReservation() throws Exception {
    AiBudgetService ledger = ledger(100, 1_000_000, 10);
    String ok =
        ledger.execute(
            UUID.randomUUID(),
            4_000,
            new AiBudgetService.LeaseAwareCall<String>() {
              @Override
              public void lease(UUID leaseId) {
                ledger.topUp(leaseId, 2_000);
              }

              @Override
              public String invoke() {
                return "candidate";
              }

              @Override
              public long usageOf(String result) {
                return -1;
              }
            });
    assertThat(ok).isEqualTo("candidate");
    // Topped-up funding settles in full when usage is unknown.
    assertThat(day().tokensUsed()).isEqualTo(6_000);
    assertThat(day().tokensReserved()).isZero();
  }

  @Test
  void settlePastEstimateRecordsHonestly() {
    // Prevention is pre-call (reserve/top-up deny); settle records the
    // provider-reported truth even past the funding, and the bound
    // violation is logged loud for re-sizing before re-arming.
    AiBudgetService ledger = ledger(100, 10_000, 10);
    UUID lease = ledger.reserve(UUID.randomUUID(), 6_000);
    ledger.settle(lease, 12_000);
    assertThat(day().tokensUsed()).isEqualTo(12_000);
    assertThat(day().tokensReserved()).isZero();
    assertThat(leaseState(lease)).isEqualTo("SETTLED");
  }

  private AiBudgetService ledger(int requests, long tokens, int concurrency) {
    AiBudgetProperties budgets = new AiBudgetProperties();
    budgets.setDailyRequests(requests);
    budgets.setDailyTokens(tokens);
    budgets.setMaxConcurrency(concurrency);
    budgets.setLeaseSeconds(3_600);
    return new AiBudgetService(appRoleDataSource(), Clock.systemUTC(), budgets);
  }

  private Day day() {
    return owner.queryForObject(
        "SELECT requests_used, tokens_used, requests_reserved, tokens_reserved"
            + " FROM ai_budget_day WHERE day = CURRENT_DATE",
        (rs, row) -> new Day(rs.getInt(1), rs.getLong(2), rs.getInt(3), rs.getLong(4)));
  }

  private String leaseState(UUID lease) {
    return owner.queryForObject(
        "SELECT state FROM ai_call_lease WHERE id = ?", String.class, lease);
  }

  record Day(int requestsUsed, long tokensUsed, int requestsReserved, long tokensReserved) {}
}
