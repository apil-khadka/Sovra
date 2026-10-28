package dev.sovra.bff;

import dev.sovra.auth.ServiceAccountController;
import dev.sovra.auth.ServiceAccountService;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.web.CurrentPrincipal;
import jakarta.validation.Valid;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Session-chain credential administration (SOV-006): the same
 * {@link ServiceAccountService} behind BFF sessions, so human trust
 * admins manage machine credentials without ever holding a Bearer
 * [REDACTED] A session compromise yields no long-lived secret — only the
 * one-time tokens it explicitly mints, each audited.
 */
@RestController
@RequestMapping("/api/bff/service-accounts")
@ConditionalOnProperty(name = "sovra.bff.enabled", havingValue = "true")
public class BffServiceAccountController {

  private final ServiceAccountService accounts;

  public BffServiceAccountController(ServiceAccountService accounts) {
    this.accounts = accounts;
  }

  @PostMapping
  public ResponseEntity<Map<String, Object>> create(
      @Valid @RequestBody ServiceAccountController.CreateRequest request) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    ServiceAccountService.CreatedAccount created =
        accounts.create(caller, request.name(), request.roles(), request.expiresAt());
    Map<String, Object> body = new LinkedHashMap<>(ServiceAccountController.view(created.account()));
    body.put("token", created.oneTimeToken());
    return ResponseEntity.status(HttpStatus.CREATED).body(body);
  }

  @GetMapping
  public ResponseEntity<List<Map<String, Object>>> list() {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    return ResponseEntity.ok(
        accounts.list(caller).stream().map(ServiceAccountController::view).toList());
  }

  @GetMapping("/{id}")
  public ResponseEntity<Map<String, Object>> get(@PathVariable("id") UUID id) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    return ResponseEntity.ok(ServiceAccountController.view(accounts.get(caller, id)));
  }

  @PostMapping("/{id}/rotate")
  public ResponseEntity<Map<String, Object>> rotate(
      @PathVariable("id") UUID id,
      @RequestBody(required = false) ServiceAccountController.RotateRequest request) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    ServiceAccountService.CreatedAccount rotated =
        accounts.rotate(caller, id, request == null ? null : request.expiresAt());
    Map<String, Object> body =
        new LinkedHashMap<>(ServiceAccountController.view(rotated.account()));
    body.put("token", rotated.oneTimeToken());
    return ResponseEntity.ok(body);
  }

  @PostMapping("/{id}/revoke")
  public ResponseEntity<Map<String, Object>> revoke(@PathVariable("id") UUID id) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    return ResponseEntity.ok(ServiceAccountController.view(accounts.revoke(caller, id)));
  }
}
