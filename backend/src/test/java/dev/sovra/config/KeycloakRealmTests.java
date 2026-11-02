package dev.sovra.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

/**
 * Production realm definition (PROD-004): TLS everywhere, no demo
 * users, no embedded secrets, brute-force and password/OTP policy
 * on, exact HTTPS origins — while keeping the exact token contract
 * (scopes, mappers, groups, ES256 keys) the BFF was tested against.
 */
class KeycloakRealmTests {

  static final Path PROD = Path.of("../deploy/production/keycloak/realm/sovra-realm.prod.json");
  static final Path DEMO = Path.of("../keycloak/realm/sovra-realm.json");

  @Test
  @SuppressWarnings("unchecked")
  void productionRealmIsHardened() throws Exception {
    assertThat(PROD).exists();
    Map<String, Object> realm =
        new ObjectMapper().readValue(Files.readString(PROD), Map.class);

    assertThat(realm.get("realm")).isEqualTo("sovra");
    assertThat(realm.get("sslRequired")).isEqualTo("all");
    assertThat(realm.get("registrationAllowed")).isEqualTo(false);

    // No demo users, no embedded credentials of any kind.
    assertThat(realm).doesNotContainKey("users");
    List<String> secrets = new ArrayList<>();
    collectSecrets(realm, secrets);
    assertThat(secrets).as("embedded secrets").isEmpty();
    assertThat(Files.readString(PROD)).doesNotContain("demo-").doesNotContain("localhost");

    // Lockout, password, and OTP policy on.
    assertThat(realm.get("bruteForceProtected")).isEqualTo(true);
    assertThat(realm.get("passwordPolicy").toString()).contains("length(14)");
    assertThat(realm.get("otpPolicyType")).isEqualTo("totp");

    // Exact HTTPS origins for the BFF client.
    Map<String, Object> client = client(realm, "sovra-bff");
    assertThat(client.get("publicClient")).isEqualTo(false);
    assertThat(client.get("standardFlowEnabled")).isEqualTo(true);
    assertThat(client.get("directAccessGrantsEnabled")).isEqualTo(false);
    List<String> redirects = (List<String>) client.get("redirectUris");
    assertThat(redirects).isNotEmpty();
    for (String redirect : redirects) {
      assertThat(redirect).startsWith("https://");
      assertThat(redirect).doesNotContain("localhost");
    }
    Map<String, Object> attributes = (Map<String, Object>) client.get("attributes");
    assertThat(attributes.get("pkce.code.challenge.method")).isEqualTo("S256");
    assertThat(attributes.get("post.logout.redirect.uris").toString()).startsWith("https://");
  }

  @Test
  @SuppressWarnings("unchecked")
  void productionRealmKeepsTheBffTokenContract() throws Exception {
    Map<String, Object> prod =
        new ObjectMapper().readValue(Files.readString(PROD), Map.class);
    Map<String, Object> demo =
        new ObjectMapper().readValue(Files.readString(DEMO), Map.class);

    // Same groups, same scopes, same claim names, same key
    // algorithm: the import must not silently drop what the BFF
    // login suite proves against the demo shape.
    assertThat(groupNames(prod)).isEqualTo(groupNames(demo));
    assertThat(scopeNames(prod)).isEqualTo(scopeNames(demo));
    assertThat(claimNames(prod)).isEqualTo(claimNames(demo));
    Map<String, Object> prodClient = client(prod, "sovra-bff");
    Map<String, Object> demoClient = client(demo, "sovra-bff");
    assertThat(prodClient.get("defaultClientScopes"))
        .isEqualTo(demoClient.get("defaultClientScopes"));
    assertThat(keyAlgorithms(prod)).isEqualTo(keyAlgorithms(demo));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> client(Map<String, Object> realm, String clientId) {
    for (Map<String, Object> client : (List<Map<String, Object>>) realm.get("clients")) {
      if (clientId.equals(client.get("clientId"))) {
        return client;
      }
    }
    throw new IllegalStateException("client missing: " + clientId);
  }

  @SuppressWarnings("unchecked")
  private static List<String> groupNames(Map<String, Object> realm) {
    return ((List<Map<String, Object>>) realm.get("groups")).stream()
        .map(group -> group.get("name").toString())
        .sorted()
        .toList();
  }

  @SuppressWarnings("unchecked")
  private static List<String> scopeNames(Map<String, Object> realm) {
    return ((List<Map<String, Object>>) realm.get("clientScopes")).stream()
        .map(scope -> scope.get("name").toString())
        .sorted()
        .toList();
  }

  @SuppressWarnings("unchecked")
  private static List<String> claimNames(Map<String, Object> realm) {
    List<String> claims = new ArrayList<>();
    for (Map<String, Object> scope : (List<Map<String, Object>>) realm.get("clientScopes")) {
      for (Map<String, Object> mapper : (List<Map<String, Object>>) scope.get("protocolMappers")) {
        claims.add(((Map<String, Object>) mapper.get("config")).get("claim.name").toString());
      }
    }
    return claims.stream().sorted().toList();
  }

  @SuppressWarnings("unchecked")
  private static List<String> keyAlgorithms(Map<String, Object> realm) {
    List<String> algorithms = new ArrayList<>();
    Map<String, Object> components = (Map<String, Object>) realm.get("components");
    for (Map<String, Object> provider :
        (List<Map<String, Object>>) components.get("org.keycloak.keys.KeyProvider")) {
      algorithms.addAll(
          (List<String>) ((Map<String, Object>) provider.get("config")).get("algorithm"));
    }
    return algorithms.stream().sorted().toList();
  }

  @SuppressWarnings("unchecked")
  private static void collectSecrets(Object node, List<String> secrets) {
    if (node instanceof Map<?, ?> map) {
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        String key = entry.getKey().toString();
        Object value = entry.getValue();
        if (("secret".equals(key) || "value".equals(key))
            && value instanceof String text
            && !text.isBlank()) {
          secrets.add(key + "=" + text.substring(0, Math.min(4, text.length())) + "...");
        } else {
          collectSecrets(value, secrets);
        }
      }
    } else if (node instanceof List<?> list) {
      for (Object item : list) {
        collectSecrets(item, secrets);
      }
    }
  }
}
