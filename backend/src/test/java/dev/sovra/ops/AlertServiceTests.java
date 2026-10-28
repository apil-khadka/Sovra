package dev.sovra.ops;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Alert derivation: stale authority and commit failure page while UP. */
class AlertServiceTests {

  private static final Instant T0 = Instant.parse("2026-06-01T12:00:00Z");

  private static ReadinessCheck fixed(String name, CheckStatus status, String code) {
    return new ReadinessCheck() {
      @Override
      public String name() {
        return name;
      }

      @Override
      public CheckResult check() {
        return new CheckResult(name, status, code, Map.of(), 1);
      }
    };
  }

  private static AlertService alertsAt(FlowReadinessService readiness, Instant now) {
    return new AlertService(readiness, Clock.fixed(now, ZoneOffset.UTC));
  }

  @Test
  void staleAuthorityRaisesHighAlert() {
    AlertService alerts =
        alertsAt(
            new FlowReadinessService(
                List.of(fixed("trust_freshness", CheckStatus.DOWN, "stale_authority"))),
            T0);

    List<AlertService.Alert> active = alerts.active();

    assertThat(active).hasSize(1);
    assertThat(active.get(0).alert()).isEqualTo("STALE_TRUST_AUTHORITY");
    assertThat(active.get(0).severity()).isEqualTo("high");
    assertThat(active.get(0).check()).isEqualTo("trust_freshness");
    assertThat(active.get(0).firstObservedAt()).isEqualTo(T0);
  }

  @Test
  void auditCommitFailureRaisesCriticalAlert() {
    AlertService alerts =
        alertsAt(
            new FlowReadinessService(
                List.of(fixed("audit_durability", CheckStatus.DOWN, "write_rejected"))),
            T0);

    List<AlertService.Alert> active = alerts.active();

    assertThat(active).hasSize(1);
    assertThat(active.get(0).alert()).isEqualTo("AUDIT_COMMIT_FAILURE");
    assertThat(active.get(0).severity()).isEqualTo("critical");
  }

  /** Mutable clock: advances time for one service instance. */
  static final class Ticking extends Clock {
    Instant now;

    Ticking(Instant start) {
      this.now = start;
    }

    @Override
    public Instant instant() {
      return now;
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }
  }

  @Test
  void firstObservedIsStableAcrossPollsAndRecoveryClears() {
    FlowReadinessService firing =
        new FlowReadinessService(List.of(fixed("database", CheckStatus.DOWN, "unreachable")));
    Ticking clock = new Ticking(T0);
    AlertService alerts = new AlertService(firing, clock);
    assertThat(alerts.active().get(0).firstObservedAt()).isEqualTo(T0);

    clock.now = T0.plusSeconds(300);
    AlertService.Alert stillFiring = alerts.active().get(0);
    assertThat(stillFiring.firstObservedAt()).isEqualTo(T0);
    assertThat(stillFiring.observedAt()).isEqualTo(T0.plusSeconds(300));

    // A fresh service instance honestly restarts the clock (crash-explicit).
    AlertService restarted = alertsAt(firing, T0.plusSeconds(600));
    assertThat(restarted.active().get(0).firstObservedAt()).isEqualTo(T0.plusSeconds(600));

    FlowReadinessService recovered =
        new FlowReadinessService(List.of(fixed("database", CheckStatus.UP, "reachable")));
    assertThat(new AlertService(recovered, clock).active()).isEmpty();
  }

  @Test
  void unknownCheckDegradesToMediumAlert() {
    AlertService alerts =
        alertsAt(
            new FlowReadinessService(
                List.of(fixed("future_check", CheckStatus.DEGRADED, "unknown"))),
            T0);

    List<AlertService.Alert> active = alerts.active();

    assertThat(active).hasSize(1);
    assertThat(active.get(0).alert()).isEqualTo("CHECK_DEGRADED");
    assertThat(active.get(0).severity()).isEqualTo("medium");
  }

  @Test
  void allUpRaisesNothing() {
    AlertService alerts =
        alertsAt(
            new FlowReadinessService(
                List.of(fixed("database", CheckStatus.UP, "reachable"))),
            T0);

    assertThat(alerts.active()).isEmpty();
  }
}
