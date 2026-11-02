package dev.sovra.admission;

import dev.sovra.auth.CurrentPrincipal;
import dev.sovra.auth.ServiceAccountPrincipal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Shared admission enforcement (PROD-006). Runs inside both security
 * chains <em>after</em> authorization, so denied requests cost no
 * budget and admitted requests never skip authorization or audit:
 *
 * <ul>
 *   <li>authenticated callers consume a per-principal and a
 *       per-tenant token from the fleet-wide JDBC buckets — hot
 *       tenants hit their own ceiling, never their neighbors';
 *   <li>anonymous callers on login, protocol, and probe paths
 *       consume coarse global buckets — abuse protection without
 *       per-IP tracking behind untrusted proxies;
 *   <li>every request holds one in-flight permit for its cost
 *       group, released no matter how the request ends.
 * </ul>
 *
 * <p>Denials are explicit: 429 with {@code Retry-After} for spent
 * budgets, 503 with {@code Retry-After} for full groups and limiter
 * outages. A dead limiter fails closed — the database outage behind
 * it has already taken the stateful paths down anyway.
 *
 * <p>Cheap public content (SPA assets, discovery, issuer keys) is
 * deliberately outside the anonymous buckets: limiting it would
 * throttle page loads, not attackers.
 */
public class AdmissionFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(AdmissionFilter.class);

  private final JdbcRateLimiter limiter;
  private final AdmissionProperties properties;
  private final InFlightGuard guard;

  public AdmissionFilter(
      JdbcRateLimiter limiter, AdmissionProperties properties, InFlightGuard guard) {
    this.limiter = limiter;
    this.properties = properties;
    this.guard = guard;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String path = request.getServletPath();
    InFlightGuard.Group group = InFlightGuard.groupFor(path);
    if (!guard.tryEnter(group)) {
      reject(request, response, 503, "overloaded", true, 1);
      return;
    }
    try {
      Optional<ServiceAccountPrincipal> caller = CurrentPrincipal.get();
      if (caller.isPresent()) {
        if (!spend(
            request,
            response,
            "principal:" + caller.get().id(),
            properties.principal())) {
          return;
        }
        if (!spend(request, response, "tenant:" + caller.get().tenantId(), properties.tenant())) {
          return;
        }
      } else {
        String anonymous = anonymousBucket(path);
        AdmissionProperties.Bucket budget = anonymousBudget(path);
        if (anonymous != null && !spend(request, response, anonymous, budget)) {
          return;
        }
      }
      // Probes cost a global bucket on top, authenticated or not:
      // readiness runs live checks per call.
      if ("/api/health/ready".equals(path)) {
        if (!spend(request, response, "probe:ready", properties.probeReady())) {
          return;
        }
      } else if ("/api/health".equals(path)) {
        if (!spend(request, response, "probe:health", properties.probeHealth())) {
          return;
        }
      }
      chain.doFilter(request, response);
    } catch (DataAccessException e) {
      log.warn("rate limiter store unreachable; failing closed");
      reject(request, response, 503, "limiter_unavailable", true, 5);
    } finally {
      guard.leave(group);
    }
  }

  private boolean spend(
      HttpServletRequest request,
      HttpServletResponse response,
      String bucket,
      AdmissionProperties.Bucket budget)
      throws IOException {
    JdbcRateLimiter.Verdict verdict =
        limiter.consume(bucket, budget.capacity(), budget.ratePerSecond(), 1.0);
    if (verdict.allowed()) {
      return true;
    }
    reject(request, response, 429, "rate_limited", true, verdict.retryAfterSeconds());
    return false;
  }

  /**
   * Anonymous quota scope for abuse-prone paths; null skips cheap
   * public content. Probes are consumed separately below for every
   * caller, so they stay out of this mapping (no double-spend).
   */
  static String anonymousBucket(String path) {
    if (path.startsWith("/oauth2/") || path.startsWith("/login/")) {
      return "anon:login";
    }
    if (path.startsWith("/api/vci/")
        || path.startsWith("/api/vp/")
        || "/.well-known/openid-credential-issuer".equals(path)) {
      return "anon:protocol";
    }
    return null;
  }

  private AdmissionProperties.Bucket anonymousBudget(String path) {
    if (path.startsWith("/oauth2/") || path.startsWith("/login/")) {
      return properties.anonymousLogin();
    }
    return properties.anonymousProtocol();
  }

  private void reject(
      HttpServletRequest request,
      HttpServletResponse response,
      int status,
      String code,
      boolean retryable,
      long retryAfterSeconds)
      throws IOException {
    response.setStatus(status);
    response.setHeader("Retry-After", Long.toString(Math.max(1, retryAfterSeconds)));
    String accept = request.getHeader("Accept");
    boolean problem = accept != null && accept.contains("application/problem+json");
    response.setContentType(
        problem ? "application/problem+json" : "application/json" + ";charset=UTF-8");
    String body;
    if (problem) {
      body =
          "{\"type\":\"about:blank\",\"title\":\""
              + code
              + "\",\"status\":"
              + status
              + ",\"code\":\""
              + code
              + "\",\"correlationId\":\""
              + dev.sovra.web.CorrelationIds.currentOrRandom()
              + "\",\"retryable\":"
              + retryable
              + "}";
    } else {
      body = "{\"error\":\"" + code + "\"}";
    }
    response.getWriter().write(body);
  }
}
