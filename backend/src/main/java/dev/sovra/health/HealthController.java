package dev.sovra.health;

import dev.sovra.ops.CheckResult;
import dev.sovra.ops.FlowReadinessService;
import dev.sovra.ops.InstanceIdentity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Public liveness probe. Reports build and fleet identity only; never
 * identity data. The instance id names the answering replica and the
 * boot id its process start, so load-balanced probes are attributable.
 */
@RestController
@RequestMapping("/api/health")
public class HealthController {

  private final String version;
  private final FlowReadinessService readiness;
  private final InstanceIdentity identity;

  public HealthController(
      @Value("${sovra.version}") String version,
      FlowReadinessService readiness,
      InstanceIdentity identity) {
    this.version = version;
    this.readiness = readiness;
    this.identity = identity;
  }

  @GetMapping
  public HealthStatus health() {
    return new HealthStatus(
        "UP", "sovra-backend", version, identity.instanceId(), identity.bootId());
  }

  /**
   * Public semantic readiness (SOV-029): liveness says the process answers,
   * readiness says the flow can proceed. 200 READY only when every
   * dependency probe is UP; otherwise 503 with the sanitized per-check
   * report so orchestrators stop routing flow traffic.
   */
  @GetMapping("/ready")
  public ResponseEntity<ReadyStatus> ready() {
    FlowReadinessService.ReadinessReport report = readiness.report();
    ReadyStatus body =
        new ReadyStatus(
            report.status(), identity.instanceId(), identity.bootId(), report.checks());
    if ("READY".equals(report.status())) {
      return ResponseEntity.ok(body);
    }
    return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(body);
  }

  public record HealthStatus(
      String status, String service, String version, String instanceId, String bootId) {}

  public record ReadyStatus(
      String status, String instanceId, String bootId, java.util.List<CheckResult> checks) {}
}
