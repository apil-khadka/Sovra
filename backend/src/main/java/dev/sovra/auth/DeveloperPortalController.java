package dev.sovra.auth;

import dev.sovra.verification.RpOutcomeService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Developer portal and RP dashboard machine chain
 * (SOV-022/SOV-025): sandbox onboarding for members,
 * RP-subset credential rotation for members, and
 * audience-scoped verification outcomes and metrics.
 * The browser desks reach the same services through the
 * BFF layer, which owns session binding; this chain
 * carries Bearer [REDACTED] only.
 */
@RestController
public class DeveloperPortalController {

  private final SandboxService sandbox;
  private final RpCredentialService credentials;
  private final RpOutcomeService outcomes;

  public DeveloperPortalController(
      SandboxService sandbox,
      RpCredentialService credentials,
      RpOutcomeService outcomes) {
    this.sandbox = sandbox;
    this.credentials = credentials;
    this.outcomes = outcomes;
  }

  public record SandboxRequest(@NotBlank String name) {}

  public record RotateRequest(Instant expiresAt) {}

  @PostMapping("/api/sandbox/accounts")
  public ResponseEntity<Map<String, Object>> createSandbox(
      @Valid @RequestBody SandboxRequest request) {
    ServiceAccountPrincipal caller = CurrentPrincipal.require();
    ServiceAccountService.CreatedAccount created =
        sandbox.createSandbox(caller, request.name());
    Map<String, Object> body =
        new LinkedHashMap<>(ServiceAccountController.view(created.account()));
    body.put("token", created.oneTimeToken());
    return ResponseEntity.status(HttpStatus.CREATED).body(body);
  }

  @GetMapping("/api/sandbox/accounts")
  public ResponseEntity<List<Map<String, Object>>> listSandbox() {
    ServiceAccountPrincipal caller = CurrentPrincipal.require();
    return ResponseEntity.ok(
        sandbox.listSandbox(caller).stream().map(ServiceAccountController::view).toList());
  }

  @GetMapping("/api/rp/apps")
  public ResponseEntity<List<Map<String, Object>>> apps() {
    ServiceAccountPrincipal caller = CurrentPrincipal.require();
    return ResponseEntity.ok(
        credentials.apps(caller).stream().map(ServiceAccountController::view).toList());
  }

  @PostMapping("/api/rp/credentials/{id}/rotate")
  public ResponseEntity<Map<String, Object>> rotate(
      @PathVariable("id") UUID id,
      @RequestBody(required = false) RotateRequest request) {
    ServiceAccountPrincipal caller = CurrentPrincipal.require();
    ServiceAccountService.CreatedAccount rotated =
        credentials.rotate(caller, id, request == null ? null : request.expiresAt());
    Map<String, Object> body =
        new LinkedHashMap<>(ServiceAccountController.view(rotated.account()));
    body.put("token", rotated.oneTimeToken());
    return ResponseEntity.ok(body);
  }

  @PostMapping("/api/rp/credentials/{id}/revoke")
  public ResponseEntity<Map<String, Object>> revoke(@PathVariable("id") UUID id) {
    ServiceAccountPrincipal caller = CurrentPrincipal.require();
    return ResponseEntity.ok(
        ServiceAccountController.view(credentials.revoke(caller, id)));
  }

  @GetMapping("/api/rp/outcomes")
  public ResponseEntity<List<Map<String, Object>>> rpOutcomes(
      @RequestParam(name = "limit", defaultValue = "20") int limit) {
    ServiceAccountPrincipal caller = CurrentPrincipal.require();
    return ResponseEntity.ok(
        outcomes.outcomes(caller, limit).stream().map(DeveloperPortalController::outcome).toList());
  }

  @GetMapping("/api/rp/metrics")
  public ResponseEntity<Map<String, Object>> rpMetrics() {
    ServiceAccountPrincipal caller = CurrentPrincipal.require();
    RpOutcomeService.MetricsView metrics = outcomes.metrics(caller);
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("total", metrics.total());
    body.put("accepted", metrics.accepted());
    body.put("rejected", metrics.rejected());
    body.put("unknown", metrics.unknown());
    return ResponseEntity.ok(body);
  }

  static Map<String, Object> outcome(RpOutcomeService.OutcomeView view) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("decisionId", view.decisionId().toString());
    body.put("requestId", view.requestId().toString());
    body.put("rpId", view.rpId());
    body.put("outcome", view.outcome());
    body.put("reasonCode", view.reasonCode());
    body.put("decidedAt", view.decidedAt().toString());
    return body;
  }
}
