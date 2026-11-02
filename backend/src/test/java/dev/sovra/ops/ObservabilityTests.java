package dev.sovra.ops;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

/**
 * Fleet identity and request correlation (PROD-011): health payloads
 * name their replica and boot, every response echoes the request id,
 * and errors plus audit rows carry it so one value joins logs,
 * errors, and evidence.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = "sovra.instance-id=obs-test")
class ObservabilityTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    client = RestClient.builder()
        .baseUrl("http://localhost:" + port)
        .requestFactory(new org.springframework.http.client.JdkClientHttpRequestFactory())
        .build();
    owner = new JdbcTemplate(ownerDataSource());
  }

  @Test
  @SuppressWarnings("unchecked")
  void healthCarriesFleetIdentity() {
    Map<String, Object> first =
        client.get().uri("/api/health").retrieve().body(Map.class);
    assertThat(first.get("status")).isEqualTo("UP");
    assertThat(first.get("instanceId")).isEqualTo("obs-test");
    assertThat(first.get("bootId").toString()).matches("[0-9a-f]{16}");
    // The boot id is stable within the process: same replica, same boot.
    Map<String, Object> second =
        client.get().uri("/api/health").retrieve().body(Map.class);
    assertThat(second.get("bootId")).isEqualTo(first.get("bootId"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void readyCarriesFleetIdentity() {
    Map<String, Object> health =
        client.get().uri("/api/health").retrieve().body(Map.class);
    var response =
        client.get().uri("/api/health/ready").retrieve().toEntity(Map.class);
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(response.getBody().get("status")).isEqualTo("READY");
    assertThat(response.getBody().get("instanceId")).isEqualTo("obs-test");
    assertThat(response.getBody().get("bootId")).isEqualTo(health.get("bootId"));
  }

  @Test
  void callerRequestIdEchoes() {
    var response = client.get()
        .uri("/api/health")
        .header("X-Request-Id", "caller-123")
        .retrieve()
        .toBodilessEntity();
    assertThat(response.getHeaders().getFirst("X-Request-Id")).isEqualTo("caller-123");
  }

  @Test
  void missingRequestIdGeneratesUuid() {
    var response =
        client.get().uri("/api/health").retrieve().toBodilessEntity();
    assertThat(response.getHeaders().getFirst("X-Request-Id")).matches(
        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
  }

  @Test
  void invalidRequestIdIsReplaced() {
    var response = client.get()
        .uri("/api/health")
        .header("X-Request-Id", "not a token; with separators")
        .retrieve()
        .toBodilessEntity();
    // Control characters and separators never echo back.
    assertThat(response.getHeaders().getFirst("X-Request-Id")).matches(
        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
  }

  @Test
  void forbiddenCarriesRequestId() {
    // No roles: authenticates, then fails authorization with a
    // problem payload (404s are deliberately bodiless).
    TestAccount nobody = TestAccounts.create(owner, "obs-nobody", Set.of());
    String requestId = "error-trace-1";
    try {
      client.get()
          .uri("/api/rp/outcomes?limit=1")
          .headers(nobody.headers())
          .header("X-Request-Id", requestId)
          .accept(org.springframework.http.MediaType.parseMediaType("application/problem+json"))
          .retrieve()
          .toBodilessEntity();
      assertThat(false).as("roleless caller must be forbidden").isTrue();
    } catch (HttpClientErrorException.Forbidden e) {
      assertThat(e.getResponseHeaders().getFirst("X-Request-Id")).isEqualTo(requestId);
      assertThat(e.getResponseBodyAsString()).contains("\"correlationId\":\"" + requestId + "\"");
    }
  }

  @Test
  void auditRowCarriesRequestId() {
    TestAccount member =
        TestAccounts.create(owner, "obs-auditor", Set.of("TENANT_MEMBER"));
    String requestId = "audit-trace-1";
    client.get()
        .uri("/api/rp/outcomes?limit=1")
        .headers(member.headers())
        .header("X-Request-Id", requestId)
        .retrieve()
        .toBodilessEntity();
    String correlation =
        owner.queryForObject(
            "SELECT correlation_id FROM audit_event WHERE actor_id = ?"
                + " AND action = 'READ_RP_REQUESTS' ORDER BY occurred_at DESC LIMIT 1",
            String.class,
            member.accountId().toString());
    assertThat(correlation).isEqualTo(requestId);
  }
}
