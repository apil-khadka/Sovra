package dev.sovra.bff;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * Fail-fast configuration checks (SOV-006): the BFF refuses to boot
 * with a blank, insecure, or drifted trust registry. Pure unit
 * tests, no Spring context.
 */
class BffConfigTests {

  static BffProperties valid(boolean enabled) {
    return new BffProperties(
        enabled,
        "https://op.example/realms/sovra",
        "sovra-bff",
        "https://app.example/login/oauth2/code/sovra",
        "https://app.example/",
        "https://op.example/realms/sovra/protocol/openid-connect/logout",
        true,
        "tenant_slug",
        "groups",
        List.of("sovra-demo"),
        Map.of("sovra-members", "TENANT_MEMBER"),
        List.of("TRUST_ADMIN"),
        List.of("webauthn"),
        "sovra");
  }

  static ClientRegistration registration(String issuer, String clientId, String redirect,
      Object algs) {
    return ClientRegistration.withRegistrationId("sovra")
        .clientId(clientId)
        .clientSecret("secret")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri(redirect)
        .scope("openid")
        .authorizationUri(issuer + "/protocol/openid-connect/auth")
        .tokenUri(issuer + "/protocol/openid-connect/token")
        .userInfoUri(issuer + "/protocol/openid-connect/userinfo")
        .jwkSetUri(issuer + "/protocol/openid-connect/certs")
        .issuerUri(issuer)
        .providerConfigurationMetadata(
            algs == null ? Map.of() : Map.of("id_token_signing_alg_values_supported", algs))
        .build();
  }

  @Test
  void validRegistryPassesSelfCheck() {
    assertThatCode(valid(true)::validateSelf).doesNotThrowAnyException();
  }

  @Test
  void disabledSkipsSelfCheck() {
    BffProperties off = new BffProperties(
        false, "", "", "", "", "", true, "", "", List.of(), Map.of(), List.of(), List.of(), "sovra");
    assertThatCode(off::validateSelf).doesNotThrowAnyException();
  }

  @Test
  void blanksAndEmptiesRejected() {
    BffProperties base = valid(true);
    assertThatThrownBy(() -> blank(base, "issuer").validateSelf())
        .isInstanceOf(IllegalStateException.class);
    assertThatThrownBy(() -> new BffProperties(
            true, base.issuer(), base.clientId(), base.redirectUri(), base.postLogoutRedirectUri(),
            base.endSessionEndpoint(), base.requireHttpsIssuer(), base.tenantClaim(),
            base.groupsClaim(), List.of(), base.groupRoleMap(), base.privilegedRoles(),
            base.hardwareAmr(), base.registrationId())
        .validateSelf()).isInstanceOf(IllegalStateException.class);
    assertThatThrownBy(() -> new BffProperties(
            true, base.issuer(), base.clientId(), base.redirectUri(), base.postLogoutRedirectUri(),
            base.endSessionEndpoint(), base.requireHttpsIssuer(), base.tenantClaim(),
            base.groupsClaim(), base.allowedTenantSlugs(), Map.of(), base.privilegedRoles(),
            base.hardwareAmr(), base.registrationId())
        .validateSelf()).isInstanceOf(IllegalStateException.class);
  }

  private static BffProperties blank(BffProperties base, String field) {
    return new BffProperties(
        true,
        "issuer".equals(field) ? " " : base.issuer(),
        base.clientId(), base.redirectUri(), base.postLogoutRedirectUri(), base.endSessionEndpoint(),
        base.requireHttpsIssuer(), base.tenantClaim(), base.groupsClaim(), base.allowedTenantSlugs(),
        base.groupRoleMap(), base.privilegedRoles(), base.hardwareAmr(), base.registrationId());
  }

  @Test
  void localhostHttpAllowedButLanHttpRejected() {
    BffProperties base = valid(true);
    BffProperties local = new BffProperties(
        true, "http://localhost:18080/realms/sovra", base.clientId(), base.redirectUri(),
        base.postLogoutRedirectUri(), "http://127.0.0.1:18080/logout", base.requireHttpsIssuer(),
        base.tenantClaim(), base.groupsClaim(), base.allowedTenantSlugs(), base.groupRoleMap(),
        base.privilegedRoles(), base.hardwareAmr(), base.registrationId());
    assertThatCode(local::validateSelf).doesNotThrowAnyException();
    BffProperties lan = new BffProperties(
        true, "http://keycloak:8080/realms/sovra", base.clientId(), base.redirectUri(),
        base.postLogoutRedirectUri(), base.endSessionEndpoint(), base.requireHttpsIssuer(),
        base.tenantClaim(), base.groupsClaim(), base.allowedTenantSlugs(), base.groupRoleMap(),
        base.privilegedRoles(), base.hardwareAmr(), base.registrationId());
    assertThatThrownBy(lan::validateSelf).isInstanceOf(IllegalStateException.class);
    BffProperties lanAllowed = new BffProperties(
        true, "http://keycloak:8080/realms/sovra", base.clientId(), base.redirectUri(),
        base.postLogoutRedirectUri(), "http://keycloak:8080/logout", false,
        base.tenantClaim(), base.groupsClaim(), base.allowedTenantSlugs(), base.groupRoleMap(),
        base.privilegedRoles(), base.hardwareAmr(), base.registrationId());
    assertThatCode(lanAllowed::validateSelf).doesNotThrowAnyException();
  }

  @Test
  void driftAgainstRegistrationRejected() {
    BffProperties properties = valid(true);
    assertThatCode(() -> BffConfigValidator.validate(properties, registration(
            properties.issuer(), properties.clientId(), properties.redirectUri(),
            List.of("ES256"))))
        .doesNotThrowAnyException();
    assertThatThrownBy(() -> BffConfigValidator.validate(properties, registration(
            "https://evil.example/", properties.clientId(), properties.redirectUri(),
            List.of("ES256"))))
        .isInstanceOf(IllegalStateException.class);
    assertThatThrownBy(() -> BffConfigValidator.validate(properties, registration(
            properties.issuer(), properties.clientId(), "https://app.example/other",
            List.of("ES256"))))
        .isInstanceOf(IllegalStateException.class);
    assertThatThrownBy(() -> BffConfigValidator.validate(properties, registration(
            properties.issuer(), properties.clientId(), properties.redirectUri(),
            List.of("RS256", "PS384"))))
        .isInstanceOf(IllegalStateException.class);
    assertThatCode(() -> BffConfigValidator.validate(properties, registration(
            properties.issuer(), properties.clientId(), properties.redirectUri(),
            List.of("PS384", "ES256", "RS256"))))
        .doesNotThrowAnyException();
    // No advertised algorithms: nothing to contradict.
    assertThatCode(() -> BffConfigValidator.validate(properties, registration(
            properties.issuer(), properties.clientId(), properties.redirectUri(), null)))
        .doesNotThrowAnyException();
  }
}
