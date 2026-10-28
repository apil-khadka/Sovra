package dev.sovra.health;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Public liveness probe. Reports build identity only; never identity data. */
@RestController
@RequestMapping("/api/health")
public class HealthController {

  private final String version;

  public HealthController(@Value("${sovra.version}") String version) {
    this.version = version;
  }

  @GetMapping
  public HealthStatus health() {
    return new HealthStatus("UP", "sovra-backend", version);
  }

  public record HealthStatus(String status, String service, String version) {}
}
