package dev.sovra.bff;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.util.List;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * Marker-only security-context storage for the BFF chain (PROD-003).
 *
 * <p>BffSessionFilter rebuilds the effective authentication from the
 * membership row on every request, so the session never needs the
 * framework's login-time context object — persisting it would only
 * drag OAuth2/OIDC object graphs through session serialization. This
 * repository stores a single marker string instead, and loads a
 * placeholder authentication whenever the marker is present.
 *
 * <p>The placeholder is load-bearing for exactly one framework
 * behavior: SessionManagementFilter re-runs session fixation
 * whenever the pre-chain context is anonymous and the post-chain
 * context is authenticated. Without a persisted marker, BFF requests
 * would rotate the session id on every call. The placeholder never
 * reaches authorization — BffSessionFilter clears the context first
 * on every request — and its lone authority grants nothing.
 */
public class BffSecurityContextRepository implements SecurityContextRepository {

  static final String MARKER_ATTR = "sovra.authenticated";

  @Override
  public SecurityContext loadContext(HttpRequestResponseHolder holder) {
    SecurityContext context = new SecurityContextImpl();
    HttpSession session = holder.getRequest().getSession(false);
    if (session != null && session.getAttribute(MARKER_ATTR) != null) {
      context.setAuthentication(
          new AnonymousAuthenticationToken(
              "sovra-session-marker",
              "sovra-session",
              List.of(new SimpleGrantedAuthority("SOVRA_SESSION_MARKER"))));
    }
    return context;
  }

  @Override
  public void saveContext(
      SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
    boolean authenticated =
        context.getAuthentication() != null
            && context.getAuthentication().isAuthenticated()
            && !(context.getAuthentication() instanceof AnonymousAuthenticationToken);
    if (!authenticated) {
      // Logout and anonymous paths clear the marker, but never
      // create a session just to clear it.
      HttpSession existing = request.getSession(false);
      if (existing != null) {
        existing.removeAttribute(MARKER_ATTR);
      }
      return;
    }
    request.getSession(true).setAttribute(MARKER_ATTR, "1");
  }

  @Override
  public boolean containsContext(HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    return session != null && session.getAttribute(MARKER_ATTR) != null;
  }
}
