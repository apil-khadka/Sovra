package dev.sovra.bff;

import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * S256 PKCE on every authorization request (SOV-006). Spring only
 * emits PKCE for public clients by default; the BFF is confidential
 * and still pins the code to the browser session, so a leaked code
 * alone authorizes nothing. The stub-OP login tests verify the
 * {@code code_verifier} against the challenge on every run.
 */
public class PkceAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

  private final OAuth2AuthorizationRequestResolver delegate;
  private final SecureRandom random = new SecureRandom();

  public PkceAuthorizationRequestResolver(ClientRegistrationRepository registrations) {
    this.delegate =
        new DefaultOAuth2AuthorizationRequestResolver(registrations, "/oauth2/authorization");
  }

  @Override
  public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
    return withPkce(delegate.resolve(request));
  }

  @Override
  public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
    return withPkce(delegate.resolve(request, clientRegistrationId));
  }

  private OAuth2AuthorizationRequest withPkce(OAuth2AuthorizationRequest authorizationRequest) {
    if (authorizationRequest == null
        || authorizationRequest.getAdditionalParameters().containsKey("code_challenge")) {
      return authorizationRequest;
    }
    String verifier = generateVerifier();
    Map<String, Object> additionalParameters =
        new HashMap<>(authorizationRequest.getAdditionalParameters());
    additionalParameters.put("code_challenge", s256(verifier));
    additionalParameters.put("code_challenge_method", "S256");
    Map<String, Object> attributes = new HashMap<>(authorizationRequest.getAttributes());
    attributes.put("code_verifier", verifier);
    return OAuth2AuthorizationRequest.from(authorizationRequest)
        .additionalParameters(additionalParameters)
        .attributes(attributes)
        .build();
  }

  private String generateVerifier() {
    byte[] raw = new byte[32];
    random.nextBytes(raw);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
  }

  private static String s256(String verifier) {
    try {
      MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
      byte[] digest = sha256.digest(verifier.getBytes(StandardCharsets.US_ASCII));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}
