package dev.sovra.config;

import dev.sovra.auth.ApiKeyAuthFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Deny-by-default HTTP security. Public: the liveness probe, the current
 * trust snapshot, and issuer verification keys (federation metadata).
 * Everything else needs a verified
 * Bearer service credential; service methods additionally enforce
 * tenant/action/object authority explicitly.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  SecurityFilterChain filterChain(HttpSecurity http, ApiKeyAuthFilter apiKeyAuthFilter)
      throws Exception {
    http
        // Stateless token API with no cookies or sessions; revisit when browser
        // cookie authentication arrives with the dashboards (SOV-021 and later).
        .csrf(csrf -> csrf.disable())
        .sessionManagement(
            sessions -> sessions.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .addFilterBefore(apiKeyAuthFilter, UsernamePasswordAuthenticationFilter.class)
        .authorizeHttpRequests(
            auth ->
                auth.requestMatchers(HttpMethod.GET, "/api/health")
                    .permitAll()
                    .requestMatchers(HttpMethod.GET, "/api/trust/snapshots/current")
                    .permitAll()
                    .requestMatchers(HttpMethod.GET, "/api/issuance/jwks.json")
                    .permitAll()
                    // Container error dispatches must not be re-authenticated:
                    // without this, framework 400s surface as 401s.
                    .requestMatchers("/error")
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
}
