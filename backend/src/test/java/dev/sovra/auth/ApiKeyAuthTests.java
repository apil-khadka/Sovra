package dev.sovra.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraPostgresBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import java.util.Map;
import java.util.Set;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApiKeyAuthTests extends SovraPostgresBase {

  @LocalServerPort int port;

  @Autowired DataSource dataSource;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
  }

  @Test
  void missingTokenIsUnauthorizedWithEmptyBody() {
    assertThatThrownBy(() -> client.get().uri("/api/whoami").retrieve().toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Unauthorized.class)
        .satisfies(e -> assertThat(((HttpClientErrorException) e).getResponseBodyAsString()).isEmpty());
  }

  @Test
  void unknownTokenIsUnauthorized() {
    assertThatThrownBy(
            () ->
                client
                    .get()
                    .uri("/api/whoami")
                    .headers(h -> h.setBearerAuth(TokenHasher.generate()))
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
  }

  @Test
  void revokedTokenIsUnauthorized() {
    TestAccount account =
        TestAccounts.create(owner, "revoked", Set.of("TENANT_MEMBER"));
    TestAccounts.revoke(owner, account.accountId());
    assertThatThrownBy(
            () ->
                client
                    .get()
                    .uri("/api/whoami")
                    .headers(account.headers())
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
  }

  @Test
  void expiredTokenIsUnauthorized() {
    TestAccount account =
        TestAccounts.create(owner, "expired", Set.of("TENANT_MEMBER"));
    owner.update(
        "UPDATE service_account SET expires_at = now() - INTERVAL '1 hour' WHERE id = ?",
        account.accountId());
    assertThatThrownBy(
            () ->
                client
                    .get()
                    .uri("/api/whoami")
                    .headers(account.headers())
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
  }

  @Test
  @SuppressWarnings("unchecked")
  void validTokenReturnsIdentityWithoutSecrets() {
    TestAccount account =
        TestAccounts.create(owner, "member", Set.of("TENANT_MEMBER", "AUDIT_READER"));
    Map<String, Object> body =
        client.get().uri("/api/whoami").headers(account.headers()).retrieve().body(Map.class);
    assertThat(body).isNotNull();
    assertThat(body.get("accountId")).isEqualTo(account.accountId().toString());
    assertThat(body.get("tenantId")).isEqualTo(account.tenantId().toString());
    assertThat(body.get("name")).isEqualTo("member");
    assertThat((Iterable<String>) body.get("roles"))
        .containsExactlyInAnyOrder("TENANT_MEMBER", "AUDIT_READER");
    assertThat(body.keySet()).doesNotContain("token", "tokenHash", "secret", "password");
  }

  @Test
  @SuppressWarnings("unchecked")
  void callerSuppliedTenantHeaderIsIgnored() {
    TestAccount attacker = TestAccounts.create(owner, "attacker", Set.of("TENANT_MEMBER"));
    TestAccount victim = TestAccounts.create(owner, "victim", Set.of("TENANT_MEMBER"));
    Map<String, Object> body =
        client
            .get()
            .uri("/api/whoami")
            .headers(
                h -> {
                  h.setBearerAuth(attacker.token());
                  h.set("X-Tenant-ID", victim.tenantId().toString());
                })
            .retrieve()
            .body(Map.class);
    assertThat(body).isNotNull();
    assertThat(body.get("tenantId")).isEqualTo(attacker.tenantId().toString());
    assertThat(body.get("accountId")).isEqualTo(attacker.accountId().toString());
  }

  @Test
  void everyProtectedEndpointDeniesAnonymous() {
    String proposalId = "00000000-0000-0000-0000-000000000000";
    assertThatThrownBy(
            () -> client.get().uri("/api/whoami").retrieve().toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
    assertThatThrownBy(
            () -> client.get().uri("/api/audit/events").retrieve().toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/trust/proposals")
                    .contentType(MediaType.APPLICATION_JSON).body("{}")
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/trust/proposals/" + proposalId + "/approve")
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/trust/snapshots/1/activate")
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
    String credentialId = "00000000-0000-0000-0000-000000000000";
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/issuance/credentials")
                    .contentType(MediaType.APPLICATION_JSON).body("{}")
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
    assertThatThrownBy(
            () -> client.get().uri("/api/issuance/credentials/" + credentialId).retrieve()
                .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
    assertThatThrownBy(
            () -> client.get().uri("/api/issuance/credentials/" + credentialId + "/status")
                .retrieve().toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
    assertThatThrownBy(
            () -> client.post().uri("/api/issuance/credentials/" + credentialId + "/revoke")
                .retrieve().toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
  }
}
