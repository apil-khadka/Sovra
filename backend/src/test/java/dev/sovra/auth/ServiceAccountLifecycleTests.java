package dev.sovra.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

/**
 * Application credential lifecycle over the machine chain (SOV-006):
 * TRUST_ADMIN-managed accounts with one-time tokens, rotation, and
 * terminal revocation. The BFF session twin is covered in
 * {@code BffLoginTests}; the service underneath is shared.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ServiceAccountLifecycleTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> create(TestAccount admin, Map<String, Object> body) {
    return client
        .post()
        .uri("/api/auth/service-accounts")
        .headers(admin.headers())
        .contentType(MediaType.APPLICATION_JSON)
        .body(body)
        .retrieve()
        .body(Map.class);
  }

  @Test
  void createReturnsOneTimeTokenThatAuthenticates() {
    TestAccount admin = TestAccounts.create(owner, "svc-admin", Set.of("TRUST_ADMIN"));
    Map<String, Object> created = create(
        admin, Map.of("name", "shop-rp", "roles", List.of("TENANT_MEMBER", "RP_CLIENT")));
    assertThat(created.get("id")).isNotNull();
    assertThat(created.get("name")).isEqualTo("shop-rp");
    String token = created.get("token").toString();
    assertThat(token).startsWith("sovra_test_");

    // The token authenticates: a member hitting an admin endpoint
    // gets 403 (authenticated, forbidden), never 401.
    try {
      client
          .get()
          .uri("/api/auth/service-accounts")
          .header("Authorization", "Bearer " + token)
          .retrieve()
          .body(String.class);
      throw new IllegalStateException("member listed accounts");
    } catch (HttpClientErrorException.Forbidden e) {
      assertThat(e.getResponseBodyAsString()).contains("MISSING_ROLE");
    }

    // Reads never return the token or its hash.
    Map<String, Object> read = client
        .get()
        .uri("/api/auth/service-accounts/" + created.get("id"))
        .headers(admin.headers())
        .retrieve()
        .body(Map.class);
    assertThat(read).doesNotContainKeys("token", "tokenHash", "token_hash");
    assertThat(read.get("revoked")).isEqualTo(Boolean.FALSE);

    Map<String, Object> audit = TestAccounts.auditRow(owner, "CREATE_SERVICE_ACCOUNT");
    assertThat(audit.get("decision")).isEqualTo("PERMIT");
    assertThat(audit.get("detail").toString()).doesNotContain(token);
  }

  @Test
  void createRejectsBadInputAndWrongCallers() {
    TestAccount admin = TestAccounts.create(owner, "svc-admin2", Set.of("TRUST_ADMIN"));
    TestAccount member = TestAccounts.create(owner, "svc-member", Set.of("TENANT_MEMBER"));
    assertThatThrownBy(() -> create(
            admin, Map.of("name", "bad", "roles", List.of("NO_SUCH_ROLE"))))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    assertThatThrownBy(() -> create(admin, Map.of("name", "  ", "roles", List.of("TENANT_MEMBER"))))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    assertThatThrownBy(() -> create(admin,
            Map.of("name", "past", "roles", List.of("TENANT_MEMBER"), "expiresAt",
                Instant.now().minusSeconds(60).toString())))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    assertThatThrownBy(() -> create(
            member, Map.of("name", "nope", "roles", List.of("TENANT_MEMBER"))))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(() -> client
            .post()
            .uri("/api/auth/service-accounts")
            .contentType(MediaType.APPLICATION_JSON)
            .body(Map.of("name", "anon", "roles", List.of("TENANT_MEMBER")))
            .retrieve()
            .body(String.class))
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
  }

  @Test
  void databaseRejectsUnknownRoles() {
    // Raw SQL bypasses ServiceAccountService validation; the V18
    // CHECKs are the last door. Both inserts are otherwise valid,
    // so the named constraint must be the one that fires.
    TestAccount admin = TestAccounts.create(owner, "svc-roles", Set.of("TRUST_ADMIN"));
    assertThatThrownBy(() -> owner.update(
            "INSERT INTO service_account (tenant_id, name, token_prefix, token_hash, roles)"
                + " VALUES (?, ?, ?, ?, ?::text[])",
            admin.tenantId(),
            "evil",
            "ab12",
            new byte[32],
            new String[] {"TYPO_ROLE"}))
        .isInstanceOf(DataIntegrityViolationException.class)
        .hasMessageContaining("service_account_roles_known");
    assertThatThrownBy(() -> owner.update(
            "INSERT INTO human_membership (tenant_id, issuer, subject, roles)"
                + " VALUES (?, ?, ?, ?::text[])",
            admin.tenantId(),
            "https://op.example/realms/sovra",
            "evil-subject",
            new String[] {"TYPO_ROLE"}))
        .isInstanceOf(DataIntegrityViolationException.class)
        .hasMessageContaining("human_membership_roles_known");
  }

  @Test
  void rotateReplacesCredentialAndRevokedStaysTerminal() {
    TestAccount admin = TestAccounts.create(owner, "svc-admin3", Set.of("TRUST_ADMIN"));
    Map<String, Object> created = create(
        admin, Map.of("name", "rot", "roles", List.of("TENANT_MEMBER")));
    String id = created.get("id").toString();
    String first = created.get("token").toString();

    Map<String, Object> rotated = client
        .post()
        .uri("/api/auth/service-accounts/" + id + "/rotate")
        .headers(admin.headers())
        .contentType(MediaType.APPLICATION_JSON)
        .body(Map.of())
        .retrieve()
        .body(Map.class);
    String second = rotated.get("token").toString();
    assertThat(second).isNotEqualTo(first);

    // Old credential dies with rotation; the new one authenticates.
    assertThatThrownBy(() -> client
            .get()
            .uri("/api/auth/service-accounts")
            .header("Authorization", "Bearer " + first)
            .retrieve()
            .body(String.class))
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
    try {
      client
          .get()
          .uri("/api/auth/service-accounts")
          .header("Authorization", "Bearer " + second)
          .retrieve()
          .body(String.class);
      throw new IllegalStateException("rotated member listed accounts");
    } catch (HttpClientErrorException.Forbidden e) {
      assertThat(e.getResponseBodyAsString()).contains("MISSING_ROLE");
    }

    Map<String, Object> revoked = client
        .post()
        .uri("/api/auth/service-accounts/" + id + "/revoke")
        .headers(admin.headers())
        .retrieve()
        .body(Map.class);
    assertThat(revoked.get("revoked")).isEqualTo(Boolean.TRUE);
    assertThatThrownBy(() -> client
            .get()
            .uri("/api/auth/service-accounts")
            .header("Authorization", "Bearer " + second)
            .retrieve()
            .body(String.class))
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);

    // Terminal: rotation of a revoked account is a conflict, and
    // revocation stays put on repeat.
    assertThatThrownBy(() -> client
            .post()
            .uri("/api/auth/service-accounts/" + id + "/rotate")
            .headers(admin.headers())
            .contentType(MediaType.APPLICATION_JSON)
            .body(Map.of())
            .retrieve()
            .body(String.class))
        .isInstanceOf(HttpClientErrorException.Conflict.class);
    Map<String, Object> again = client
        .post()
        .uri("/api/auth/service-accounts/" + id + "/revoke")
        .headers(admin.headers())
        .retrieve()
        .body(Map.class);
    assertThat(again.get("revoked")).isEqualTo(Boolean.TRUE);

    assertThat(TestAccounts.auditRow(owner, "ROTATE_SERVICE_ACCOUNT").get("decision"))
        .isEqualTo("PERMIT");
    assertThat(TestAccounts.auditRow(owner, "REVOKE_SERVICE_ACCOUNT").get("decision"))
        .isEqualTo("PERMIT");
  }

  @Test
  void accountsAreTenantScoped() {
    TestAccount adminA = TestAccounts.create(owner, "svc-ten-a", Set.of("TRUST_ADMIN"));
    TestAccount adminB = TestAccounts.create(owner, "svc-ten-b", Set.of("TRUST_ADMIN"));
    Map<String, Object> created = create(
        adminA, Map.of("name", "scoped", "roles", List.of("TENANT_MEMBER")));
    String id = created.get("id").toString();

    // Cross-tenant reads/rotates/revokes are empty 404s: no existence
    // signal leaks across the boundary.
    assertThatThrownBy(() -> client
            .get()
            .uri("/api/auth/service-accounts/" + id)
            .headers(adminB.headers())
            .retrieve()
            .body(String.class))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
    assertThatThrownBy(() -> client
            .post()
            .uri("/api/auth/service-accounts/" + id + "/revoke")
            .headers(adminB.headers())
            .retrieve()
            .body(String.class))
        .isInstanceOf(HttpClientErrorException.NotFound.class);

    List<Map> listed = client
        .get()
        .uri("/api/auth/service-accounts")
        .headers(adminB.headers())
        .retrieve()
        .body(List.class);
    assertThat(listed).isNotNull();
    assertThat(listed.stream().map(entry -> entry.get("id").toString()).toList())
        .doesNotContain(id);
  }

  @Test
  void unknownIdsAreEmpty404() {
    TestAccount admin = TestAccounts.create(owner, "svc-admin4", Set.of("TRUST_ADMIN"));
    assertThatThrownBy(() -> client
            .get()
            .uri("/api/auth/service-accounts/" + UUID.randomUUID())
            .headers(admin.headers())
            .retrieve()
            .body(String.class))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
  }
}
