package dev.sovra.auth;

import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.web.CurrentPrincipal;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Machine-chain credential administration (SOV-006). TRUST_ADMIN
 * Bearer [REDACTED] create, inspect, rotate, and revoke service accounts;
 * the same operations serve BFF sessions from
 * {@code BffServiceAccountController}. Tokens are returned once and
 * never readable afterwards.
 */
@RestController
@RequestMapping("/api/auth/service-accounts")
public class ServiceAccountController {

  private final ServiceAccountService accounts;

  public ServiceAccountController(ServiceAccountService accounts) {
    this.accounts = accounts;
  }

  public record CreateRequest(
      @NotBlank String name, @NotEmpty Set<String> roles, Instant expiresAt) {}

  public record RotateRequest(Instant expiresAt) {}

  @PostMapping
  public ResponseEntity<Map<String, Object>> create(@Valid @RequestBody CreateRequest request) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    ServiceAccountService.CreatedAccount created =
        accounts.create(caller, request.name(), request.roles(), request.expiresAt());
    Map<String, Object> body = new LinkedHashMap<>(view(created.account()));
    body.put("token", created.oneTimeToken());
    return ResponseEntity.status(HttpStatus.CREATED).body(body);
  }

  @GetMapping
  public ResponseEntity<List<Map<String, Object>>> list() {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    return ResponseEntity.ok(accounts.list(caller).stream().map(ServiceAccountController::view).toList());
  }

  @GetMapping("/{id}")
  public ResponseEntity<Map<String, Object>> get(@PathVariable("id") UUID id) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    return ResponseEntity.ok(view(accounts.get(caller, id)));
  }

  @PostMapping("/{id}/rotate")
  public ResponseEntity<Map<String, Object>> rotate(
      @PathVariable("id") UUID id, @RequestBody(required = false) RotateRequest request) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    ServiceAccountService.CreatedAccount rotated =
        accounts.rotate(caller, id, request == null ? null : request.expiresAt());
    Map<String, Object> body = new LinkedHashMap<>(view(rotated.account()));
    body.put("token", rotated.oneTimeToken());
    return ResponseEntity.ok(body);
  }

  @PostMapping("/{id}/revoke")
  public ResponseEntity<Map<String, Object>> revoke(@PathVariable("id") UUID id) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    return ResponseEntity.ok(view(accounts.revoke(caller, id)));
  }

  public static Map<String, Object> view(ServiceAccountService.AccountView account) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("id", account.id().toString());
    body.put("name", account.name());
    body.put("roles", account.roles().stream().sorted().toList());
    body.put("revoked", account.revoked());
    body.put("expiresAt", account.expiresAt() == null ? null : account.expiresAt().toString());
    body.put("createdAt", account.createdAt().toString());
    return body;
  }
}
