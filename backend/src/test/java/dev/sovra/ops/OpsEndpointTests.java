package dev.sovra.ops;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraPostgresBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Operations endpoints over HTTP (SOV-029): public sanitized readiness,
 * role-gated alerts and telemetry, and the contained canary.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OpsEndpointTests extends SovraPostgresBase {

  @LocalServerPort int port;

  @Autowired TrustService trust;

  @Autowired ObjectMapper mapper;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() throws Exception {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
    IssuanceFixtures.ensureSyntheticIssuer(owner, trust, mapper);
    owner.update(
        "INSERT INTO issuer_signing_key (issuer_id, key_id, key_version, public_key_jwk, status)"
            + " VALUES (?, 'ops-key', 1, '{}'::jsonb, 'ACTIVE') ON CONFLICT DO NOTHING",
        IssuanceFixtures.ISSUER_ID);
  }

  private JsonNode getJson(String path, TestAccount account) throws Exception {
    var spec = client.get().uri(path);
    if (account != null) {
      spec.headers(account.headers());
    }
    return mapper.readTree(spec.retrieve().body(String.class));
  }

  @Test
  void readinessIsPublicAndSanitized() throws Exception {
    JsonNode report = getJson("/api/health/ready", null);

    assertThat(report.get("status").asString()).isEqualTo("READY");
    assertThat(report.get("checks").size()).isEqualTo(7);
    for (JsonNode check : report.get("checks")) {
      assertThat(check.get("status").asString()).isEqualTo("UP");
      assertThat(check.get("durationMs").asLong()).isGreaterThanOrEqualTo(0);
    }
    String raw = mapper.writeValueAsString(report);
    assertThat(raw)
        .doesNotContain(
            "SQLException", "PSQLException", "password", "secret", "stackTrace", "Exception");
  }

  @Test
  void alertsRequireAnAuditRole() throws Exception {
    assertThatThrownBy(() -> getJson("/api/alerts", null))
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);

    TestAccount member = TestAccounts.create(owner, "ops-member", Set.of("TENANT_MEMBER"));
    assertThatThrownBy(() -> getJson("/api/alerts", member))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);

    TestAccount reader =
        TestAccounts.createInTenant(owner, member.tenantId(), "ops-reader", Set.of("AUDIT_READER"));
    JsonNode alerts = getJson("/api/alerts", reader);
    assertThat(alerts.isArray()).isTrue();
    for (JsonNode alert : alerts) {
      assertThat(alert.has("alert")).isTrue();
      assertThat(alert.has("severity")).isTrue();
      assertThat(alert.has("firstObservedAt")).isTrue();
    }
  }

  @Test
  void telemetrySummaryIsTenantScopedAndRoleGated() throws Exception {
    assertThatThrownBy(() -> getJson("/api/telemetry/summary", null))
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);

    TestAccount rp = TestAccounts.create(owner, "ops-rp", Set.of("RP_CLIENT"));
    assertThatThrownBy(() -> getJson("/api/telemetry/summary", rp))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);

    TestAccount member = TestAccounts.create(owner, "ops-member", Set.of("TENANT_MEMBER"));
    JsonNode summary = getJson("/api/telemetry/summary", member);
    assertThat(summary.has("stages")).isTrue();
    assertThat(summary.has("reasons")).isTrue();
    assertThat(summary.get("reasons").isArray()).isTrue();
  }

  @Test
  void canaryRunsContainedAndRequiresAMemberRole() throws Exception {
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/telemetry/canary")
                    .contentType(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .body(String.class))
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);

    TestAccount rp = TestAccounts.create(owner, "ops-canary-rp", Set.of("RP_CLIENT"));
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/telemetry/canary")
                    .headers(rp.headers())
                    .contentType(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .body(String.class))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);

    TestAccount member = TestAccounts.create(owner, "ops-canary", Set.of("TENANT_MEMBER"));
    String raw =
        client
            .post()
            .uri("/api/telemetry/canary")
            .headers(member.headers())
            .contentType(MediaType.APPLICATION_JSON)
            .retrieve()
            .body(String.class);
    JsonNode report = mapper.readTree(raw);

    assertThat(report.get("synthetic").asBoolean()).isTrue();
    assertThat(report.get("mode").asString()).isEqualTo("FIXTURE");
    assertThat(report.get("contained").asBoolean()).isTrue();
    JsonNode channels = report.get("channels");
    assertThat(channels.get("logs").asBoolean()).isTrue();
    assertThat(channels.get("errors").asBoolean()).isTrue();
    assertThat(channels.get("metrics").asBoolean()).isTrue();
    assertThat(channels.get("modelFixture").get("label").asString()).isEqualTo("FIXTURE");
    assertThat(channels.get("modelFixture").get("contained").asBoolean()).isTrue();
  }
}
