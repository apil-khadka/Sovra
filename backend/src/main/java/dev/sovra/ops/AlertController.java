package dev.sovra.ops;

import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.authz.ResourceRef;
import dev.sovra.web.CurrentPrincipal;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Active security alerts for operations review. Alerts are global derived
 * state (fixed names, severities, and codes — no tenant data), readable by
 * audit and trust-administration roles.
 */
@RestController
@RequestMapping("/api/alerts")
public class AlertController {

  private final AuthorizationService authz;
  private final AlertService alerts;

  public AlertController(AuthorizationService authz, AlertService alerts) {
    this.authz = authz;
    this.alerts = alerts;
  }

  @GetMapping
  public ResponseEntity<List<AlertService.Alert>> active() {
    var caller = CurrentPrincipal.get();
    caller.orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    authz.enforce(caller, Action.READ_ALERTS, ResourceRef.global("ops", "alerts"));
    return ResponseEntity.ok(alerts.active());
  }
}
