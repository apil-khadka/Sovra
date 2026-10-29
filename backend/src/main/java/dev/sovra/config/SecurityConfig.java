package dev.sovra.config;

import dev.sovra.auth.ApiKeyAuthFilter;
import dev.sovra.auth.HumanMembershipRepository;
import dev.sovra.bff.BffCsrfCookieFilter;
import dev.sovra.bff.BffLoginHandlers;
import dev.sovra.bff.BffLoginService;
import dev.sovra.bff.BffSessionFilter;
import dev.sovra.bff.PkceAuthorizationRequestResolver;
import dev.sovra.web.SpaRoutes;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
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
      HumanMembershipRepository memberships)
      throws Exception {
    http.securityMatcher("/oauth2/**", "/login/**", "/api/bff/**")
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

  @Bean
  @Order(2)
  SecurityFilterChain filterChain(HttpSecurity http, ApiKeyAuthFilter apiKeyAuthFilter)
      throws Exception {
    http
        // Stateless token API with no cookies or sessions.
        .csrf(csrf -> csrf.disable())
        .sessionManagement(
            sessions -> sessions.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .addFilterBefore(apiKeyAuthFilter, UsernamePasswordAuthenticationFilter.class)
        .authorizeHttpRequests(
            auth ->
                auth.requestMatchers(HttpMethod.GET, "/api/health")
                    .permitAll()
                    .requestMatchers(HttpMethod.GET, "/api/health/ready")
                    .permitAll()
                    .requestMatchers(HttpMethod.GET, "/api/trust/snapshots/current")
                    .permitAll()
                    .requestMatchers(HttpMethod.GET, "/api/issuance/jwks.json")
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
        .httpBasic(Customizer.withDefaults())
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
}
