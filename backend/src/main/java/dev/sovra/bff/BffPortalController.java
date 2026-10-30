package dev.sovra.bff;

import dev.sovra.auth.DeveloperPortalController;
import dev.sovra.web.DiscoveryController;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Developer portal and RP dashboard behind BFF sessions
 * (SOV-022/SOV-025): sandbox onboarding, RP credential
 * rotation, outcomes, and metrics for browser members.
 * Every call delegates to the machine controllers — one
 * wire shape on both chains, so the portal desks can
 * never drift from the published API.
 */
@RestController
@RequestMapping("/api/bff/portal")
@ConditionalOnProperty(name = "sovra.bff.enabled", havingValue = "true")
public class BffPortalController {

  private final DeveloperPortalController portal;
  private final DiscoveryController discovery;

  public BffPortalController(DeveloperPortalController portal, DiscoveryController discovery) {
    this.portal = portal;
    this.discovery = discovery;
  }

  @GetMapping("/discovery")
  public ResponseEntity<Map<String, Object>> discovery() {
    return discovery.discovery();
  }

  @PostMapping("/sandbox/accounts")
  public ResponseEntity<Map<String, Object>> createSandbox(
      @Valid @RequestBody DeveloperPortalController.SandboxRequest request) {
    return portal.createSandbox(request);
  }

  @GetMapping("/sandbox/accounts")
  public ResponseEntity<List<Map<String, Object>>> listSandbox() {
    return portal.listSandbox();
  }

  @GetMapping("/rp/apps")
  public ResponseEntity<List<Map<String, Object>>> apps() {
    return portal.apps();
  }

  @PostMapping("/rp/credentials/{id}/rotate")
  public ResponseEntity<Map<String, Object>> rotate(
      @PathVariable("id") UUID id,
      @RequestBody(required = false) DeveloperPortalController.RotateRequest request) {
    return portal.rotate(id, request);
  }

  @PostMapping("/rp/credentials/{id}/revoke")
  public ResponseEntity<Map<String, Object>> revoke(@PathVariable("id") UUID id) {
    return portal.revoke(id);
  }

  @GetMapping("/rp/outcomes")
  public ResponseEntity<List<Map<String, Object>>> outcomes(
      @RequestParam(name = "limit", defaultValue = "20") int limit) {
    return portal.rpOutcomes(limit);
  }

  @GetMapping("/rp/metrics")
  public ResponseEntity<Map<String, Object>> rpMetrics() {
    return portal.rpMetrics();
  }
}
