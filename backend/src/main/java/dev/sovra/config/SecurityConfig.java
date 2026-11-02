package dev.sovra.config;

import dev.sovra.admission.AdmissionFilter;
import dev.sovra.admission.AdmissionProperties;
import dev.sovra.admission.InFlightGuard;
import dev.sovra.admission.JdbcRateLimiter;
import dev.sovra.auth.ApiKeyAuthFilter;
import dev.sovra.auth.HumanMembershipRepository;
import dev.sovra.bff.BffCsrfCookieFilter;
import dev.sovra.bff.BffLoginHandlers;
import dev.sovra.bff.BffLoginService;
import dev.sovra.bff.BffSecurityContextRepository;
import dev.sovra.bff.BffSessionFilter;
import dev.sovra.bff.PkceAuthorizationRequestResolver;
import dev.sovra.web.SpaRoutes;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

/**
 * Deny-by-default HTTP security over two chains.
 *
 * <p>Machine API (stateless Bearer): the liveness and semantic
 * readiness probes, the current trust snapshot, and issuer
 * verification keys are public; everything else needs a verified
 * Bearer [REDACTED] credential, and service methods additionally enforce
 * tenant/action/object authority explicitly.
 *
 * <p>Browser BFF (sessions, SOV-006): login dance plus
 * {@code /api/bff/**} behind server-side sessions, Secure/HttpOnly
 * cookies, fixation migration, and CSRF tokens. The chains are
 * mutually exclusive: sessions never authenticate the machine API
 * (stateless, never reads a session) and Bearer [REDACTED] never
 * authenticate the BFF (the session filter clears non-session auth
 * first).
 *
 * <p>Packaged SPA (SOV-041): GET/HEAD outside the reserved
 * API/auth/operations prefixes is public static content served
 * from this same origin; the matcher below shares its boundary
 * with the resource fallback ({@link SpaRoutes}).
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  @Order(1)
  @ConditionalOnProperty(name = "sovra.bff.enabled", havingValue = "true")
  SecurityFilterChain bffChain(
      HttpSecurity http,
      ClientRegistrationRepository clients,
      BffLoginService logins,
      HumanMembershipRepository memberships,
      JdbcRateLimiter limiter,
      AdmissionProperties admission,
      InFlightGuard guard)
      throws Exception {
    http.securityMatcher("/oauth2/**", "/login/**", "/api/bff/**")
        // The SPA probes /api/bff/me before login. Saving that 401
        // would send the browser to raw JSON after the callback.
        // BFF requests are APIs, not navigable login destinations.
        .requestCache(cache -> cache.requestCache(
            new org.springframework.security.web.savedrequest.NullRequestCache()))
        // SPA pattern: the CSRF cookie is readable by script so the
        // frontend can echo it; the session cookie stays HttpOnly.
        // The plain request handler is deliberate: Security 7
        // defaults to the XOR (BREACH) handler, whose masked tokens
        // only reach server-rendered templates — a cookie-echo SPA
        // can never submit them. The OAuth2 dance itself is
        // state-protected, not CSRF-token protected.
        .csrf(
            csrf ->
                csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                    .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                    .ignoringRequestMatchers("/oauth2/**", "/login/**"))
        .sessionManagement(
            sessions ->
                sessions
                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                    .sessionFixation(fixation -> fixation.migrateSession()))
        // PROD-003: the session holds a marker, not the framework
        // context object (see BffSecurityContextRepository):
        // BffSessionFilter rebuilds the effective authentication from
        // the membership row on every request, so persisting the
        // OIDC object graph would only bloat the shared row. The
        // marker is what stops SessionManagementFilter from
        // re-running fixation on every call. Explicit-save mode keeps
        // the per-request rebuild out of the store.
        .securityContext(
            context ->
                context
                    .requireExplicitSave(true)
                    .securityContextRepository(new BffSecurityContextRepository()))
        .oauth2Login(
            oauth ->
                oauth
                    .authorizationEndpoint(
                        endpoint ->
                            endpoint.authorizationRequestResolver(
                                new PkceAuthorizationRequestResolver(clients)))
                    .successHandler(BffLoginHandlers.success(logins))
                    .failureHandler(
                        (request, response, exception) -> {
                          String code;
                          String detail = "";
                          if (exception instanceof
                              org.springframework.security.oauth2.core.OAuth2AuthenticationException failure) {
                            code = failure.getError().getErrorCode();
                            detail = String.valueOf(failure.getError().getDescription());
                            detail = detail.substring(0, Math.min(200, detail.length()));
                          } else {
                            code = exception.getClass().getSimpleName();
                          }
                          org.slf4j.LoggerFactory.getLogger(SecurityConfig.class)
                              .warn("BFF OAuth2 login failed: {} {}", code, detail);
                          response.sendRedirect("/?auth_error=UNTRUSTED_ISSUER");
                        }))
        // Session-only: drops any servlet-level Bearer-derived auth
        // before applying the membership session.
        .addFilterBefore(
            new BffSessionFilter(memberships), UsernamePasswordAuthenticationFilter.class)
        // Always set the readable CSRF cookie, even on safe reads.
        .addFilterAfter(
            new BffCsrfCookieFilter(),
            org.springframework.security.web.csrf.CsrfFilter.class)
        // PROD-006: admission runs after authorization, so denied
        // requests cost no budget and admitted requests never skip
        // authorization or audit.
        .addFilterAfter(
            new AdmissionFilter(limiter, admission, guard),
            org.springframework.security.web.access.intercept.AuthorizationFilter.class)
        .authorizeHttpRequests(
            auth ->
                auth.requestMatchers("/oauth2/**", "/login/**")
                    .permitAll()
                    .requestMatchers("/error")
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .exceptionHandling(
            exceptions ->
                exceptions.authenticationEntryPoint(
                    (request, response, authException) -> response.setStatus(401)));
    return http.build();
  }

  /**
   * The machine filter runs ONLY inside the machine chain (see
   * {@code filterChain} below). Without this registration, Boot
   * auto-registers the {@code @Component} with the servlet container
   * at lowest precedence, so it re-runs after the security chain on
   * EVERY path — including BFF paths, where a valid Bearer would
   * overwrite the session identity {@code BffSessionFilter} just
   * established. Proven by
   * {@code BffLoginTests#bearerNeverOverridesSessionOnBffPaths}.
   */
  @Bean
  FilterRegistrationBean<ApiKeyAuthFilter> apiKeyAuthFilterRegistration(
      ApiKeyAuthFilter apiKeyAuthFilter) {
    FilterRegistrationBean<ApiKeyAuthFilter> registration =
        new FilterRegistrationBean<>(apiKeyAuthFilter);
    registration.setEnabled(false);
    return registration;
  }

  @Bean
  @Order(2)
  SecurityFilterChain filterChain(
      HttpSecurity http,
      ApiKeyAuthFilter apiKeyAuthFilter,
      JdbcRateLimiter limiter,
      AdmissionProperties admission,
      InFlightGuard guard,
      @Value("${management.server.port:-1}") int managementPort)
      throws Exception {
    http
        // Stateless token API with no cookies or sessions.
        .csrf(csrf -> csrf.disable())
        .sessionManagement(
            sessions -> sessions.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .addFilterBefore(apiKeyAuthFilter, UsernamePasswordAuthenticationFilter.class)
        // PROD-006: admission after authorization (see the BFF chain
        // comment for why this position matters).
        .addFilterAfter(
            new AdmissionFilter(limiter, admission, guard),
            org.springframework.security.web.access.intercept.AuthorizationFilter.class)
        .authorizeHttpRequests(
            auth ->
                auth.requestMatchers(HttpMethod.GET, "/api/health")
                    .permitAll()
                    .requestMatchers(HttpMethod.GET, "/api/health/ready")
                    .permitAll()
                    // PROD-011: fleet scrape/health, reachable only on
                    // the private management port (SOVRA_MANAGEMENT_PORT;
                    // never published by ingress) and never on the
                    // public application port. See the matcher below.
                    .requestMatchers(new ManagementPortActuatorMatcher(managementPort))
                    .permitAll()
                    .requestMatchers(HttpMethod.GET, "/api/trust/snapshots/current")
                    .permitAll()
                    .requestMatchers(HttpMethod.GET, "/api/issuance/jwks.json")
                    .permitAll()
                    // Developer portal discovery (SOV-022): static
                    // posture only, no identity data, no auth.
                    .requestMatchers(HttpMethod.GET, "/api/discovery")
                    .permitAll()
                    // OpenID4VCI/OpenID4VP wallet calls (SOV-036): public
                    // metadata and grant/token/nonce/response endpoints.
                    // The services bind every call to its single-use
                    // grant, token, or session; no service account is
                    // involved on these paths.
                    .requestMatchers(
                        HttpMethod.GET,
                        "/.well-known/openid-credential-issuer",
                        "/api/vp/jwks.json",
                        "/api/vp/requests/*/object")
                    .permitAll()
                    .requestMatchers(
                        HttpMethod.POST,
                        "/api/vci/token",
                        "/api/vci/nonce",
                        "/api/vci/credential",
                        "/api/vp/responses/*")
                    .permitAll()
                    // Container error dispatches must not be re-authenticated:
                    // without this, framework 400s surface as 401s.
                    .requestMatchers("/error")
                    .permitAll()
                    // Packaged SPA (SOV-041): same-origin static
                    // assets and history routes. Reserved prefixes
                    // stay authenticated; nothing else here is a
                    // controller, so there is nothing to bypass.
                    .requestMatchers(new SpaStaticRequestMatcher())
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .exceptionHandling(
            exceptions ->
                exceptions.authenticationEntryPoint(
                    (request, response, authException) -> response.setStatus(401)));
    return http.build();
  }

  /**
   * GET/HEAD over public static paths (SOV-041). Safe methods only:
   * mutations outside the reserved prefixes still require
   * authentication and 401 anonymously.
   */
  static final class SpaStaticRequestMatcher
      implements org.springframework.security.web.util.matcher.RequestMatcher {
    @Override
    public boolean matches(HttpServletRequest request) {
      String method = request.getMethod();
      if (!"GET".equals(method) && !"HEAD".equals(method)) {
        return false;
      }
      return SpaRoutes.isPublicStaticPath(request.getRequestURI());
    }
  }

  /**
   * PROD-011: actuator reads are public only on the management port.
   * The match is on the socket local port, not on Host headers, so it
   * cannot be spoofed; when management is disabled (-1) or random
   * (0) nothing matches and actuator stays behind authentication.
   */
  static final class ManagementPortActuatorMatcher
      implements org.springframework.security.web.util.matcher.RequestMatcher {

    private static final java.util.Set<String> PATHS =
        java.util.Set.of("/actuator/health", "/actuator/info", "/actuator/prometheus");

    private final int managementPort;

    ManagementPortActuatorMatcher(int managementPort) {
      this.managementPort = managementPort;
    }

    @Override
    public boolean matches(HttpServletRequest request) {
      if (managementPort <= 0 || !"GET".equals(request.getMethod())) {
        return false;
      }
      if (request.getLocalPort() != managementPort) {
        return false;
      }
      return PATHS.contains(request.getRequestURI());
    }
  }
}
