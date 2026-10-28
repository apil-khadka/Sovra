package dev.sovra.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

/**
 * The whole HTTP stack booted as the least-privilege role: authentication,
 * tenant isolation, and public metadata all hold under production-shaped
 * grants with row-level security enforced by the database.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AppRoleHttpTests extends SovraAppRoleBase {

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
  @SuppressWarnings("unchecked")
  void whoamiWorksAsAppRole() {
    TestAccount account = TestAccounts.create(owner, "approle", Set.of("AUDIT_READER"));
    Map<String, Object> body =
        client.get().uri("/api/whoami").headers(account.headers()).retrieve().body(Map.class);
    assertThat(body.get("tenantId")).isEqualTo(account.tenantId().toString());
  }

  @Test
  @SuppressWarnings("unchecked")
  void auditListShowsOnlyOwnTenant() {
    TestAccount accountA = TestAccounts.create(owner, "iso-a", Set.of("AUDIT_READER"));
    TestAccount accountB = TestAccounts.create(owner, "iso-b", Set.of("AUDIT_READER"));
    owner.update(
        "INSERT INTO audit_event (tenant_id, actor_type, actor_id, action, resource_type,"
            + " decision, reason_code, policy_version) VALUES (?, 't', 'a', 'SEEDED', 'r',"
            + " 'PERMIT', 'PERMIT', 1)",
        accountB.tenantId());

    List<Map<String, Object>> rows =
        (List<Map<String, Object>>)
            (List<?>)
                client
                    .get()
                    .uri("/api/audit/events")
                    .headers(accountA.headers())
                    .retrieve()
                    .body(List.class);
    assertThat(rows).isNotNull();
    assertThat(rows).allSatisfy(row -> assertThat(row.get("tenant_id")).isNull());
    for (Map<String, Object> row : rows) {
      assertThat(row).doesNotContainEntry("action", "SEEDED");
    }
  }

  @Test
  void trustCurrentStaysPublic() {
    try {
      client.get().uri("/api/trust/snapshots/current").retrieve().toBodilessEntity();
    } catch (HttpClientErrorException.NotFound e) {
      assertThat(e.getResponseBodyAsString()).isEmpty();
    }
  }
}
