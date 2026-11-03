package dev.sovra.tenancy;

import dev.sovra.auth.CurrentPrincipal;
import dev.sovra.tenancy.TenantHoldService.HoldView;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Tenant-scoped legal-hold desk (PROD-010). Trust admins set and
 * release their own tenant's hold; auditors read that tenant's
 * state. A hold suspends vault destruction and audit archival —
 * never protocol-state purges, which carry no content.
 */
@RestController
@RequestMapping("/api/tenants")
public class TenantHoldController {

  private final TenantHoldService holds;

  public TenantHoldController(TenantHoldService holds) {
    this.holds = holds;
  }

  public record HoldRequest(@NotNull Boolean held) {}

  @PutMapping("/{id}/legal-hold")
  public ResponseEntity<Map<String, Object>> setHold(
      @PathVariable("id") UUID id, @Valid @RequestBody HoldRequest request) {
    var caller = CurrentPrincipal.require();
    return ResponseEntity.ok(body(holds.setHold(caller, id, request.held())));
  }

  @GetMapping("/holds")
  public ResponseEntity<Map<String, Object>> list() {
    var caller = CurrentPrincipal.require();
    List<Map<String, Object>> items = new ArrayList<>();
    for (HoldView view : holds.list(caller)) {
      items.add(body(view));
    }
    return ResponseEntity.ok(Map.of("holds", items));
  }

  private Map<String, Object> body(HoldView view) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("tenantId", view.tenantId().toString());
    body.put("slug", view.slug());
    body.put("legalHold", view.legalHold());
    return body;
  }
}
