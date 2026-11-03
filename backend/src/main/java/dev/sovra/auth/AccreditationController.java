package dev.sovra.auth;

import dev.sovra.auth.AccreditationService.AccreditationView;
import dev.sovra.auth.AccreditationService.Approved;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Accredited RP onboarding desk (PROD-015). Operators request with
 * exact roles/origins/audiences; trust admins approve, reject, or
 * revoke. Approval mints the bound credential and returns its only
 * plaintext appearance — the stored form is a hash.
 */
@RestController
@RequestMapping("/api/accreditations")
public class AccreditationController {

  private final AccreditationService accreditations;

  public AccreditationController(AccreditationService accreditations) {
    this.accreditations = accreditations;
  }

  public record AccreditationRequest(
      @NotBlank String orgName, Set<String> roles, List<String> origins, List<String> audiences) {}

  public record DecideRequest(Instant expiresAt) {}

  @PostMapping
  public ResponseEntity<Map<String, Object>> request(
      @Valid @RequestBody AccreditationRequest request) {
    var caller = CurrentPrincipal.require();
    AccreditationView view = accreditations.request(
        caller, request.orgName(), request.roles(), request.origins(), request.audiences());
    return ResponseEntity.ok(body(view));
  }

  @PostMapping("/{id}/approve")
  public ResponseEntity<Map<String, Object>> approve(
      @PathVariable("id") UUID id, @RequestBody(required = false) DecideRequest request) {
    var caller = CurrentPrincipal.require();
    Approved approved =
        accreditations.approve(caller, id, request == null ? null : request.expiresAt());
    Map<String, Object> body = body(approved.accreditation());
    body.put("oneTimeToken", approved.oneTimeToken());
    return ResponseEntity.ok(body);
  }

  @PostMapping("/{id}/reject")
  public ResponseEntity<Map<String, Object>> reject(@PathVariable("id") UUID id) {
    var caller = CurrentPrincipal.require();
    return ResponseEntity.ok(body(accreditations.reject(caller, id)));
  }

  @PostMapping("/{id}/revoke")
  public ResponseEntity<Map<String, Object>> revoke(@PathVariable("id") UUID id) {
    var caller = CurrentPrincipal.require();
    return ResponseEntity.ok(body(accreditations.revoke(caller, id)));
  }

  @GetMapping("/{id}")
  public ResponseEntity<Map<String, Object>> get(@PathVariable("id") UUID id) {
    var caller = CurrentPrincipal.require();
    return ResponseEntity.ok(body(accreditations.get(caller, id)));
  }

  @GetMapping
  public ResponseEntity<Map<String, Object>> list() {
    var caller = CurrentPrincipal.require();
    List<Map<String, Object>> items = new ArrayList<>();
    for (AccreditationView view : accreditations.list(caller)) {
      items.add(body(view));
    }
    return ResponseEntity.ok(Map.of("accreditations", items));
  }

  private Map<String, Object> body(AccreditationView view) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("accreditationId", view.id().toString());
    body.put("orgName", view.orgName());
    body.put("roles", view.roles().stream().sorted().toList());
    body.put("origins", view.origins());
    body.put("audiences", view.audiences());
    body.put("state", view.state().name());
    body.put("requestedBy", view.requestedBy());
    body.put("decidedBy", view.decidedBy());
    body.put(
        "decidedAt", view.decidedAt() == null ? null : view.decidedAt().toString());
    body.put(
        "credentialId",
        view.credentialId() == null ? null : view.credentialId().toString());
    body.put("createdAt", view.createdAt().toString());
    return body;
  }
}
