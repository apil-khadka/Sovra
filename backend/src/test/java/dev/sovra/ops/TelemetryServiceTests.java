package dev.sovra.ops;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.issuance.InvalidIssuanceException;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

/** Stage timing aggregates: math, outcome classification, tenant isolation. */
class TelemetryServiceTests {

  private static TelemetryService telemetry() {
    // record/summary/time never touch the database; reason counts do.
    return new TelemetryService(new JdbcTemplate());
  }

  @Test
  void aggregatesCountPercentilesMaxAndOutcomes() {
    TelemetryService telemetry = telemetry();
    UUID tenant = UUID.randomUUID();
    for (int i = 1; i <= 100; i++) {
      telemetry.record(
          tenant,
          TelemetryService.Stage.ISSUANCE_ISSUE,
          i,
          i % 2 == 0 ? TelemetryService.Outcome.OK : TelemetryService.Outcome.REJECTED);
    }

    Map<String, TelemetryService.StageSummary> summary = telemetry.summary(tenant);

    assertThat(summary).containsOnlyKeys("ISSUANCE_ISSUE");
    TelemetryService.StageSummary stage = summary.get("ISSUANCE_ISSUE");
    assertThat(stage.count()).isEqualTo(100);
    assertThat(stage.p50Ms()).isEqualTo(50);
    assertThat(stage.p95Ms()).isEqualTo(95);
    assertThat(stage.maxMs()).isEqualTo(100);
    assertThat(stage.outcomes())
        .containsEntry("OK", 50L)
        .containsEntry("REJECTED", 50L)
        .containsEntry("DENIED", 0L)
        .containsEntry("ERROR", 0L);
  }

  @Test
  void tenantsAreIsolatedAndEmptyIsEmpty() {
    TelemetryService telemetry = telemetry();
    UUID first = UUID.randomUUID();
    UUID second = UUID.randomUUID();
    telemetry.record(first, TelemetryService.Stage.CONSENT_DECIDE, 5, TelemetryService.Outcome.OK);

    assertThat(telemetry.summary(first)).containsOnlyKeys("CONSENT_DECIDE");
    assertThat(telemetry.summary(second)).isEmpty();
    assertThat(telemetry.summary(UUID.randomUUID())).isEmpty();
  }

  @Test
  void recordIsNullSafeAndClampsNegativeDurations() {
    TelemetryService telemetry = telemetry();
    UUID tenant = UUID.randomUUID();
    telemetry.record(null, TelemetryService.Stage.ISSUANCE_ISSUE, 1, TelemetryService.Outcome.OK);
    telemetry.record(tenant, null, 1, TelemetryService.Outcome.OK);
    telemetry.record(tenant, TelemetryService.Stage.ISSUANCE_ISSUE, 1, null);
    telemetry.record(tenant, TelemetryService.Stage.ISSUANCE_ISSUE, -50, TelemetryService.Outcome.OK);

    TelemetryService.StageSummary stage = telemetry.summary(tenant).get("ISSUANCE_ISSUE");
    assertThat(stage.count()).isEqualTo(1);
    assertThat(stage.maxMs()).isEqualTo(0);
  }

  @Test
  void timeClassifiesOutcomesAndRethrows() {
    TelemetryService telemetry = telemetry();
    UUID tenant = UUID.randomUUID();
    Set<Class<? extends RuntimeException>> rejections = Set.of(InvalidIssuanceException.class);

    String ok =
        telemetry.time(tenant, TelemetryService.Stage.ISSUANCE_ISSUE, rejections, () -> "done");
    assertThat(ok).isEqualTo("done");
    assertThatThrownBy(
            () ->
                telemetry.time(
                    tenant,
                    TelemetryService.Stage.ISSUANCE_ISSUE,
                    rejections,
                    () -> {
                      throw new ForbiddenException(ReasonCode.MISSING_ROLE);
                    }))
        .isInstanceOf(ForbiddenException.class);
    assertThatThrownBy(
            () ->
                telemetry.time(
                    tenant,
                    TelemetryService.Stage.ISSUANCE_ISSUE,
                    rejections,
                    () -> {
                      throw new InvalidIssuanceException("bad");
                    }))
        .isInstanceOf(InvalidIssuanceException.class);
    assertThatThrownBy(
            () ->
                telemetry.time(
                    tenant,
                    TelemetryService.Stage.ISSUANCE_ISSUE,
                    rejections,
                    () -> {
                      throw new IllegalStateException("boom");
                    }))
        .isInstanceOf(IllegalStateException.class);

    TelemetryService.StageSummary stage = telemetry.summary(tenant).get("ISSUANCE_ISSUE");
    assertThat(stage.count()).isEqualTo(4);
    assertThat(stage.outcomes())
        .containsEntry("OK", 1L)
        .containsEntry("DENIED", 1L)
        .containsEntry("REJECTED", 1L)
        .containsEntry("ERROR", 1L);
  }

  @Test
  void samplesAreBoundedPerStage() {
    TelemetryService telemetry = telemetry();
    UUID tenant = UUID.randomUUID();
    for (int i = 0; i < TelemetryService.MAX_SAMPLES_PER_STAGE + 100; i++) {
      telemetry.record(tenant, TelemetryService.Stage.VERIFICATION_VERIFY, 1,
          TelemetryService.Outcome.OK);
    }

    TelemetryService.StageSummary stage = telemetry.summary(tenant).get("VERIFICATION_VERIFY");
    // Outcome counters are exact; the duration ring holds the last 512.
    assertThat(stage.count()).isEqualTo(TelemetryService.MAX_SAMPLES_PER_STAGE);
    assertThat(stage.outcomes()).containsEntry("OK",
        (long) TelemetryService.MAX_SAMPLES_PER_STAGE + 100);
    assertThat(stage.p50Ms()).isEqualTo(1);
  }
}
