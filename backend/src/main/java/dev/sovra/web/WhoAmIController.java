package dev.sovra.web;

import dev.sovra.auth.CurrentPrincipal;
import dev.sovra.auth.ServiceAccountPrincipal;
import java.util.Map;
import java.util.Set;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Authenticated caller identity. Carries no secrets or credentials. */
@RestController
@RequestMapping("/api/whoami")
public class WhoAmIController {

  @GetMapping
  public ResponseEntity<Map<String, Object>> whoami() {
    ServiceAccountPrincipal principal =
        CurrentPrincipal.require();
    return ResponseEntity.ok(
        Map.of(
            "accountId", principal.id().toString(),
            "tenantId", principal.tenantId().toString(),
            "name", principal.name(),
            "roles", Set.copyOf(principal.roles())));
  }
}
