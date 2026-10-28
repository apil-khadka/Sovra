package dev.sovra.bff;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;

/**
 * ES256-only ID-token decoding (SOV-006, SOV-001 section 1). Spring
 * Security defaults to RS256 and ignores the provider's advertised
 * algorithms, so the BFF pins the expected algorithm explicitly: our
 * allowlisted OP mints ES256, and anything else fails closed at
 * decode time. Picked up by the login configurer automatically; the
 * drift validator additionally asserts the advertised algorithm.
 */
@Configuration
@ConditionalOnProperty(name = "sovra.bff.enabled", havingValue = "true")
public class BffDecoderFactory {

  @Bean
  JwtDecoderFactory<ClientRegistration> bffJwtDecoderFactory() {
    OidcIdTokenDecoderFactory factory = new OidcIdTokenDecoderFactory();
    factory.setJwsAlgorithmResolver(registration -> SignatureAlgorithm.ES256);
    return factory;
  }
}
