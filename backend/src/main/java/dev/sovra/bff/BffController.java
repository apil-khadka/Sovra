package dev.sovra.bff;

import dev.sovra.audit.AuditService;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ResourceRef;
import dev.sovra.authz.Role;
import dev.sovra.auth.CurrentPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Session surface for browser users (SOV-006). Tokens stay
 * server-side in the session; the browser holds only the session
 * cookie plus the CSRF cookie. Machine Bearer [REDACTED] never
 * authenticate here (see {@link BffSessionFilter}).
 */
@RestController
@RequestMapping("/api/bff")
@ConditionalOnProperty(name = "sovra.bff.enabled", havingValue = "true")
public class BffController {

  private final BffProperties properties;
  private final AuditService audit;
  private final AuthorizationService authz;

  public BffController(BffProperties properties, AuditService audit, AuthorizationService authz) {
    this.properties = properties;
    this.audit = audit;
    this.authz = authz;
  }

  /** Current session identity, roles, and authentication context. */
  @GetMapping("/me")
  public ResponseEntity<Map<String, Object>> me(HttpServletRequest request) {
    ServiceAccountPrincipal principal = current();
    if (principal == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    HttpSession session = request.getSession(false);
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("displayName", principal.name());
    body.put("tenantId", principal.tenantId().toString());
    body.put("roles", principal.roles().stream().sorted().map(Role::name).toList());
    body.put("amr", session == null ? List.of() : session.getAttribute(BffLoginService.SESSION_AMR));
    body.put("authTime", session == null ? null : session.getAttribute(BffLoginService.SESSION_AUTH_TIME));
    return ResponseEntity.ok(body);
  }

  /**
   * Local logout plus RP-initiated OP logout URL. The session dies
   * here; the frontend then navigates to {@code endSessionUrl} so the
   * provider session dies too instead of silently re-authenticating
   * the next login.
   */
  @PostMapping("/logout")
  public ResponseEntity<Map<String, Object>> logout(HttpServletRequest request) {
    ServiceAccountPrincipal principal = current();
    HttpSession session = request.getSession(false);
    String idToken = session == null ? null : (String) session.getAttribute(BffLoginService.SESSION_ID_TOKEN);
    if (principal != null) {
      audit.record(
          principal,
          Action.BFF_LOGOUT,
          ResourceRef.tenantScoped("bff-session", principal.id().toString(), principal.tenantId()),
          Decision.permit(authz.policyVersion()),
          "",
          Map.of());
    }
    if (session != null) {
      session.invalidate();
    }
    SecurityContextHolder.clearContext();
    String endSessionUrl = properties.endSessionEndpoint()
        + "?id_token_hint=" + (idToken == null ? "" : urlEncode(idToken))
        + "&post_logout_redirect_uri=" + urlEncode(properties.postLogoutRedirectUri());
    return ResponseEntity.ok(Map.of("loggedOut", true, "endSessionUrl", endSessionUrl));
  }

  private ServiceAccountPrincipal current() {
    return CurrentPrincipal.get().orElse(null);
  }

  private static String urlEncode(String value) {
    return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
  }
}
