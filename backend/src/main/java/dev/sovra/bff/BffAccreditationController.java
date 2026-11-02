package dev.sovra.bff;

import dev.sovra.auth.AccreditationController.DecideRequest;
import dev.sovra.auth.AccreditationService;
import dev.sovra.auth.AccreditationService.AccreditationView;
import dev.sovra.auth.AccreditationService.Approved;
import dev.sovra.auth.CurrentPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Interactive accreditation approval (PROD-015). Minting production
 * RP credentials is a privileged decision, so the interactive path
 * requires step-up: the session must carry a hardware-bound method
 * AND a fresh authentication. Stale or weak sessions get {@code
 * step_up_required} and re-authenticate; this sets the pattern other
 * BFF privileged actions follow.
 */
@RestController
@RequestMapping("/api/bff/accreditations")
public class BffAccreditationController {

  static final Duration STEP_UP_MAX_AGE = Duration.ofMinutes(15);

  private final AccreditationService accreditations;
  private final BffProperties properties;
  private final Clock clock;

  public BffAccreditationController(
      AccreditationService accreditations, BffProperties properties, Clock clock) {
    this.accreditations = accreditations;
    this.properties = properties;
    this.clock = clock;
  }

  @PostMapping("/{id}/approve")
  public ResponseEntity<Map<String, Object>> approve(
      @PathVariable("id") UUID id,
      @RequestBody(required = false) DecideRequest request,
      HttpServletRequest http) {
    var caller = CurrentPrincipal.require();
    requireStepUp(http);
    Approved approved =
        accreditations.approve(caller, id, request == null ? null : request.expiresAt());
    Map<String, Object> body = body(approved.accreditation());
    body.put("oneTimeToken", approved.oneTimeToken());
    return ResponseEntity.ok(body);
  }

  @PostMapping("/{id}/reject")
  public ResponseEntity<Map<String, Object>> reject(
      @PathVariable("id") UUID id, HttpServletRequest http) {
    var caller = CurrentPrincipal.require();
    requireStepUp(http);
    return ResponseEntity.ok(body(accreditations.reject(caller, id)));
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

  private void requireStepUp(HttpServletRequest http) {
    HttpSession session = http.getSession(false);
    if (session == null) {
      throw new StepUpRequiredException("no session to step up from");
    }
    Object amr = session.getAttribute(BffLoginService.SESSION_AMR);
    boolean hardware =
        amr instanceof List<?> methods
            && methods.stream()
                .anyMatch(method -> properties.hardwareAmr().contains(String.valueOf(method)));
    if (!hardware) {
      throw new StepUpRequiredException("hardware-bound authentication is required");
    }
    Instant authenticated = null;
    Object authTime = session.getAttribute(BffLoginService.SESSION_AUTH_TIME);
    if (authTime != null) {
      try {
        authenticated = Instant.parse(String.valueOf(authTime));
      } catch (java.time.format.DateTimeParseException e) {
        authenticated = null;
      }
    }
    Instant now = clock.instant();
    if (authenticated == null
        || authenticated.isAfter(now)
        || Duration.between(authenticated, now).compareTo(STEP_UP_MAX_AGE) > 0) {
      throw new StepUpRequiredException("fresh authentication is required");
    }
  }

  private Map<String, Object> body(AccreditationView view) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("accreditationId", view.id().toString());
    body.put("orgName", view.orgName());
    body.put("roles", view.roles().stream().sorted().toList());
    body.put("origins", view.origins());
    body.put("audiences", view.audiences());
    body.put("state", view.state());
    body.put("requestedBy", view.requestedBy());
    body.put("decidedBy", view.decidedBy());
    body.put("decidedAt", view.decidedAt() == null ? null : view.decidedAt().toString());
    body.put(
        "credentialId", view.credentialId() == null ? null : view.credentialId().toString());
    body.put("createdAt", view.createdAt().toString());
    return body;
  }
}
