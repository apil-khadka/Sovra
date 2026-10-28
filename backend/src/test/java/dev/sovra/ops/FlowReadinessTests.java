package dev.sovra.ops;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.health.HealthController;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

/**
 * Readiness aggregation without a database: one failing check closes
 * readiness, hostile detail is sanitized, and the controller maps
 * NOT_READY to 503 while liveness stays untouched.
 */
class FlowReadinessTests {

  private static ReadinessCheck fixed(String name, CheckResult result) {
    return new ReadinessCheck() {
      @Override
      public String name() {
        return name;
      }

      @Override
      public CheckResult check() {
        return result;
      }
    };
  }

  @Test
  void allUpIsReady() {
    FlowReadinessService service =
        new FlowReadinessService(
            List.of(
                fixed("a", CheckResult.up("a", "ok", Map.of(), 1)),
                fixed("b", CheckResult.up("b", "ok", Map.of(), 2))));

    FlowReadinessService.ReadinessReport report = service.report();

    assertThat(report.status()).isEqualTo("READY");
    assertThat(report.checks()).hasSize(2);
  }

  @Test
  void oneDownClosesReadiness() {
    FlowReadinessService service =
        new FlowReadinessService(
            List.of(
                fixed("a", CheckResult.up("a", "ok", Map.of(), 1)),
                fixed("trust_freshness",
                    CheckResult.down("trust_freshness", "stale_authority", Map.of(), 4))));

    FlowReadinessService.ReadinessReport report = service.report();

    assertThat(report.status()).isEqualTo("NOT_READY");
  }

  @Test
  void degradedClosesReadinessAndEmptyIsNeverReady() {
    FlowReadinessService degraded =
        new FlowReadinessService(
            List.of(fixed("a", CheckResult.degraded("a", "freeze", Map.of(), 1))));
    assertThat(degraded.report().status()).isEqualTo("NOT_READY");
    assertThat(new FlowReadinessService(List.of()).report().status()).isEqualTo("NOT_READY");
  }

  @Test
  void hostileDetailIsSanitizedBeforeReporting() {
    FlowReadinessService service =
        new FlowReadinessService(
            List.of(
                fixed(
                    "a",
                    CheckResult.up(
                        "a",
                        "ok",
                        Map.of("token", "leak-me", "blob", new byte[] {9}, "n", 1L),
                        1))));

    CheckResult result = service.report().checks().get(0);

    assertThat(result.detail()).doesNotContainKey("token");
    assertThat(result.detail().get("blob")).isEqualTo("redacted:byte[]");
    assertThat(result.detail()).containsEntry("n", 1L);
  }

  @Test
  void controllerMapsReadyTo200AndNotReadyTo503() {
    HealthController readyController =
        new HealthController(
            "0.1.0",
            new FlowReadinessService(
                List.of(fixed("a", CheckResult.up("a", "ok", Map.of(), 1)))));
    HealthController notReadyController =
        new HealthController(
            "0.1.0",
            new FlowReadinessService(
                List.of(fixed("a", CheckResult.down("a", "unreachable", Map.of(), 1)))));

    assertThat(readyController.ready().getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(readyController.ready().getBody().status()).isEqualTo("READY");
    assertThat(notReadyController.ready().getStatusCode())
        .isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    assertThat(notReadyController.ready().getBody().status()).isEqualTo("NOT_READY");
    // Liveness is independent of readiness: the process probe stays UP.
    assertThat(notReadyController.health().status()).isEqualTo("UP");
  }
}
