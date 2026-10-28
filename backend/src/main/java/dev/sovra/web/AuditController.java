package dev.sovra.web;

import dev.sovra.audit.AuditEventRepository;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.authz.ResourceRef;
import java.util.List;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Own-tenant audit listing for evidence review (SOV-035). */
@RestController
@RequestMapping("/api/audit/events")
public class AuditController {

  private final AuthorizationService authz;
  private final AuditEventRepository events;

  public AuditController(AuthorizationService authz, AuditEventRepository events) {
    this.authz = authz;
    this.events = events;
  }

  @GetMapping
  public ResponseEntity<List<Map<String, Object>>> list(
      @RequestParam(defaultValue = "50") int limit) {
    var caller = CurrentPrincipal.get();
    var tenantId =
        caller.orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS)).tenantId();
    authz.enforce(
        caller, Action.READ_AUDIT, ResourceRef.tenantScoped("audit", "events", tenantId));
    return ResponseEntity.ok(events.listRecent(tenantId, limit));
  }
}
