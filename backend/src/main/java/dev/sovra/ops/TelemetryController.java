package dev.sovra.ops;

import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.authz.ResourceRef;
import dev.sovra.auth.CurrentPrincipal;
import java.util.List;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Sanitized operations telemetry. The summary carries only fixed stage and
 * outcome names with durations and counts for the caller's own tenant; the
 * canary exercises the containment paths with a server-side sentinel that
 * is never echoed. Neither surface accepts caller input.
 */
@RestController
@RequestMapping("/api/telemetry")
public class TelemetryController {

  private final AuthorizationService authz;
  private final TelemetryService telemetry;
  private final CanaryService canary;

  public TelemetryController(
      AuthorizationService authz, TelemetryService telemetry, CanaryService canary) {
    this.authz = authz;
    this.telemetry = telemetry;
    this.canary = canary;
  }

  @GetMapping("/summary")
  public ResponseEntity<TelemetrySummary> summary() {
    var caller = CurrentPrincipal.get();
    var principal = caller.orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    authz.enforce(
        caller,
        Action.READ_TELEMETRY,
        ResourceRef.tenantScoped("ops", "telemetry", principal.tenantId()));
    return ResponseEntity.ok(
        new TelemetrySummary(
            telemetry.summary(principal.tenantId()), telemetry.reasonCounts(principal.tenantId())));
  }

  @PostMapping("/canary")
  public ResponseEntity<CanaryService.CanaryReport> canary() {
    var caller = CurrentPrincipal.get();
    var principal = caller.orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    authz.enforce(
        caller,
        Action.RUN_CANARY,
        ResourceRef.tenantScoped("ops", "canary", principal.tenantId()));
    return ResponseEntity.ok(canary.run());
  }

  public record TelemetrySummary(
      Map<String, TelemetryService.StageSummary> stages, List<Map<String, Object>> reasons) {}
}
