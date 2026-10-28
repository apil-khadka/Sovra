package dev.sovra.bff;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.stereotype.Component;

/**
 * Configuration-drift gate (SOV-006): the BFF trust registry must
 * agree exactly with the Spring OAuth2 client registration. Any
 * mismatch fails startup loudly instead of logging into the wrong
 * provider, audience, or redirect.
 */
@Component
@ConditionalOnProperty(name = "sovra.bff.enabled", havingValue = "true")
public class BffConfigValidator implements ApplicationListener<ApplicationReadyEvent> {

  private static final Logger log = LoggerFactory.getLogger(BffConfigValidator.class);

  private final BffProperties properties;
  private final ClientRegistrationRepository registrations;

  public BffConfigValidator(
      BffProperties properties, ClientRegistrationRepository registrations) {
    this.properties = properties;
    this.registrations = registrations;
  }

  @Override
  public void onApplicationEvent(ApplicationReadyEvent event) {
    properties.validateSelf();
    ClientRegistration registration = find(properties.registrationId());
    validate(properties, registration);
    log.info("BFF trust registry matches OAuth2 registration '{}'", properties.registrationId());
  }

  private ClientRegistration find(String registrationId) {
    if (registrations instanceof InMemoryClientRegistrationRepository inMemory) {
      ClientRegistration found = inMemory.findByRegistrationId(registrationId);
      if (found != null) {
        return found;
      }
    }
    throw new IllegalStateException(
        "sovra.bff.registration-id '" + registrationId + "' has no OAuth2 client registration");
  }

  /** Pure drift check, unit-tested without Spring. */
  static void validate(BffProperties properties, ClientRegistration registration) {
    match("issuer", properties.issuer(), registration.getProviderDetails().getIssuerUri());
    match("client-id", properties.clientId(), registration.getClientId());
    match("redirect-uri", properties.redirectUri(), registration.getRedirectUri());
    // The decoder factory pins ES256; ES256 must stay advertised,
    // so a provider-side algorithm removal fails startup instead of
    // failing logins one by one. Order is the provider's business.
    Object advertised =
        registration.getProviderDetails().getConfigurationMetadata()
            .get("id_token_signing_alg_values_supported");
    if (advertised instanceof java.util.List<?> algs && !algs.isEmpty()
        && algs.stream().noneMatch("ES256"::equals)) {
      throw new IllegalStateException(
          "OP no longer advertises ES256 id_token_signing_alg_values_supported: " + algs);
    }
  }

  private static void match(String name, String expected, String actual) {
    if (!expected.equals(actual)) {
      throw new IllegalStateException(
          "sovra.bff." + name + " '" + expected + "' does not match OAuth2 registration '"
              + actual + "'");
    }
  }
}
