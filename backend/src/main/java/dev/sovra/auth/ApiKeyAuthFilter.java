package dev.sovra.auth;

import dev.sovra.tenancy.TenantContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Bearer API-token authentication. Resolves the credential to a service
 * account, binds the tenant context, and clears it at request end. Caller
 * headers claiming identity or tenancy are ignored by design.
 */
@Component
public class ApiKeyAuthFilter extends OncePerRequestFilter {

  static final String HEADER = "Authorization";
  static final String SCHEME = "Bearer ";

  private final ServiceAccountRepository accounts;
  private final Clock clock;

  public ApiKeyAuthFilter(ServiceAccountRepository accounts, Clock clock) {
    this.accounts = accounts;
    this.clock = clock;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    try {
      authenticate(request);
      chain.doFilter(request, response);
    } finally {
      SecurityContextHolder.clearContext();
      TenantContext.clear();
    }
  }

  private void authenticate(HttpServletRequest request) {
    String header = request.getHeader(HEADER);
    if (header == null || !header.startsWith(SCHEME)) {
      return;
    }
    String token = header.substring(SCHEME.length()).trim();
    if (token.isEmpty()) {
      return;
    }
    Instant now = clock.instant();
    for (ServiceAccountRepository.AccountRow row : accounts.findByPrefix(TokenHasher.prefix(token))) {
      if (TokenHasher.matches(token, row.tokenHash()) && row.live(now)) {
        ServiceAccountPrincipal principal = row.principal();
        SecurityContextHolder.getContext()
            .setAuthentication(new ServiceAccountAuthentication(principal));
        TenantContext.set(principal);
        return;
      }
    }
    // Unknown, revoked, or expired: stay anonymous; entry points deny.
  }
}
