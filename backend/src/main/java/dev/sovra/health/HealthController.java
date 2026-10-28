package dev.sovra.health;

import dev.sovra.ops.FlowReadinessService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Public liveness probe. Reports build identity only; never identity data. */
@RestController
@RequestMapping("/api/health")
public class HealthController {

  private final String version;
  private final FlowReadinessService readiness;

  public HealthController(
      @Value("${sovra.version}") String version, FlowReadinessService readiness) {
    this.version = version;
    this.readiness = readiness;
  }

  @GetMapping
  public HealthStatus health() {
    return new HealthStatus("UP", "sovra-backend", version);
  }

  /**
   * Public semantic readiness (SOV-029): liveness says the process answers,
   * readiness says the flow can proceed. 200 READY only when every
   * dependency probe is UP; otherwise 503 with the sanitized per-check
   * report so orchestrators stop routing flow traffic.
   */
  @GetMapping("/ready")
  public ResponseEntity<FlowReadinessService.ReadinessReport> ready() {
    FlowReadinessService.ReadinessReport report = readiness.report();
    if ("READY".equals(report.status())) {
      return ResponseEntity.ok(report);
    }
    return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(report);
  }

  public record HealthStatus(String status, String service, String version) {}
}
