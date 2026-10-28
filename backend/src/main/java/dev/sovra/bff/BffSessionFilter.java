package dev.sovra.bff;

import dev.sovra.auth.HumanMembershipRepository;
import dev.sovra.auth.HumanMembershipRepository.MembershipRow;
import dev.sovra.auth.ServiceAccountAuthentication;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.tenancy.TenantContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Optional;
import java.util.UUID;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Session authentication for the BFF chain only. Instantiated in
 * {@code SecurityConfig}, never a bean: auto-registration would run
 * it on the machine API too.
 *
 * <p>The chain is session-only by construction: any servlet-level
 * Bearer-derived authentication is cleared first, so machine
 * credentials can never satisfy a BFF endpoint. Membership rows are
 * reloaded on every request — roles and revocation take effect on the
 * next call, never at session age.
 */
public class BffSessionFilter extends OncePerRequestFilter {

  private final HumanMembershipRepository memberships;

  public BffSessionFilter(HumanMembershipRepository memberships) {
    this.memberships = memberships;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    SecurityContextHolder.clearContext();
    try {
      authenticate(request);
      chain.doFilter(request, response);
    } finally {
      SecurityContextHolder.clearContext();
      TenantContext.clear();
    }
  }

  private void authenticate(HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    if (session == null) {
      return;
    }
    Object raw = session.getAttribute(BffLoginService.SESSION_MEMBERSHIP);
    if (!(raw instanceof String membershipId)) {
      return;
    }
    UUID id;
    try {
      id = UUID.fromString(membershipId);
    } catch (IllegalArgumentException e) {
      session.invalidate();
      return;
    }
    Optional<MembershipRow> found = memberships.findLive(id);
    if (found.isEmpty() || !found.get().live()) {
      // Revoked or vanished mid-session: kill the session, stay
      // anonymous; entry points deny.
      session.invalidate();
      return;
    }
    ServiceAccountPrincipal principal = found.get().principal();
    SecurityContextHolder.getContext()
        .setAuthentication(new ServiceAccountAuthentication(principal));
    TenantContext.set(principal);
  }
}
