package dev.sovra.ops;

import java.util.List;
import org.springframework.stereotype.Service;

/**
 * Semantic flow readiness (SOV-029). Liveness (the process answers HTTP)
 * says nothing about whether the identity-evidence flow can proceed; this
 * service runs every dependency probe and reports READY only when all are
 * UP. A single failing check closes readiness so orchestrators stop
 * routing flow traffic while liveness stays green.
 */
@Service
public class FlowReadinessService {

  private final List<ReadinessCheck> checks;

  public FlowReadinessService(List<ReadinessCheck> checks) {
    this.checks = List.copyOf(checks);
  }

  public ReadinessReport report() {
    // Defense in depth: every check detail passes the output sanitizer so
    // a future check cannot leak dependency internals into the probe.
    List<CheckResult> results =
        checks.stream()
            .map(ReadinessCheck::check)
            .map(
                r ->
                    new CheckResult(
                        r.name(),
                        r.status(),
                        r.code(),
                        OpsSanitizer.sanitizeObjects(r.detail()),
                        r.durationMs()))
            .toList();
    boolean ready =
        !results.isEmpty() && results.stream().allMatch(r -> r.status() == CheckStatus.UP);
    return new ReadinessReport(ready ? "READY" : "NOT_READY", results);
  }

  public record ReadinessReport(String status, List<CheckResult> checks) {}
}
