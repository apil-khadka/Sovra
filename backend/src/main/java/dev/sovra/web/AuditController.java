package dev.sovra.web;

import dev.sovra.auth.CurrentPrincipal;
import dev.sovra.audit.AuditCursor;
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

/**
 * Audit listing for evidence review (SOV-035): the caller's tenant rows
 * plus platform rows for global actions (trust registry), so a global
 * change reads as one chain from any tenant. Newest first over the
 * stable {@code (occurred_at, id)} ordering; {@code limit} is bounded
 * to 1..100 (default 50) and {@code cursor} pages with an opaque
 * keyset position (SOV-015, IF-11).
 */
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
      @RequestParam(defaultValue = "50") int limit,
      @RequestParam(required = false) String cursor) {
    var caller = CurrentPrincipal.get();
    var principal = caller.orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    authz.enforce(
        caller,
        Action.READ_AUDIT,
        ResourceRef.tenantScoped("audit", "events", principal.tenantId()));
    AuditCursor position = cursor == null ? null : AuditCursor.decode(cursor);
    return ResponseEntity.ok(events.listRecent(principal.tenantId(), limit, position));
  }
}
