package dev.sovra.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Assigns the request correlation id first, so denials, errors, and
 * audit rows written downstream all carry it. Reads one header and
 * allocates nothing per body byte, so it runs ahead of even the
 * body-size guard.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorrelationIdFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String candidate = request.getHeader(CorrelationIds.HEADER);
    String requestId =
        CorrelationIds.valid(candidate) ? candidate : UUID.randomUUID().toString();
    CorrelationIds.set(requestId);
    response.setHeader(CorrelationIds.HEADER, requestId);
    try {
      chain.doFilter(request, response);
    } finally {
      CorrelationIds.clear();
    }
  }
}
