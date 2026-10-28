package dev.sovra.bff;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Forces CSRF token generation on every BFF response so the
 * readable CSRF cookie is always set — including on safe-method
 * reads, which otherwise never mint a token and would leave the
 * SPA with nothing to echo on its first mutation. Runs after
 * {@code CsrfFilter} in the BFF chain only; never a bean, so it
 * cannot attach to the stateless machine chain.
 */
public class BffCsrfCookieFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
    if (token != null) {
      token.getToken();
    }
    chain.doFilter(request, response);
  }
}
