package dev.sovra.ops;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraPostgresBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
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
 * Telemetry follows the real flow (SOV-029): issuance records sanitized
 * stage timings with classified outcomes, reason metrics mirror the
 * durable audit log, and tenants never see each other's aggregates.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TelemetryFlowTests extends SovraPostgresBase {

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
  }

  private String issue(TestAccount issuer, String key, Map<String, Object> body) {
    return client
        .post()
        .uri("/api/issuance/credentials")
        .headers(
            h -> {
              issuer.headers().accept(h);
              h.set("Idempotency-Key", key);
            })
        .contentType(MediaType.APPLICATION_JSON)
        .body(body)
        .retrieve()
        .body(String.class);
  }

  private Map<String, Object> issueBody(IssuanceFixtures.HolderKeys holder, String key, String proof)
      throws Exception {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("issuerId", IssuanceFixtures.ISSUER_ID);
    body.put("vct", IssuanceFixtures.ADULT_VCT);
    body.put("holderJwk", mapper.convertValue(holder.jwk(), Map.class));
    body.put("holderProof", proof);
    body.put("claims", Map.of("adultOver18", Boolean.TRUE));
    body.put("expiresAt", Instant.now().plusSeconds(3600).toString());
    return body;
  }

  private JsonNode summary(TestAccount reader) throws Exception {
    String raw =
        client
            .get()
            .uri("/api/telemetry/summary")
            .headers(reader.headers())
            .retrieve()
            .body(String.class);
    return mapper.readTree(raw);
  }

  @Test
  void issuanceRecordsTimingsReasonsAndTenantIsolation() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "tm-issuer", Set.of("ISSUER_OPS"));
    TestAccount reader =
        TestAccounts.createInTenant(owner, issuer.tenantId(), "tm-reader", Set.of("TENANT_MEMBER"));
    TestAccount outsider = TestAccounts.create(owner, "tm-outsider", Set.of("TENANT_MEMBER"));

    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String okKey = "tm-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    String proof = IssuanceFixtures.proof(holder, okKey, IssuanceFixtures.ADULT_VCT, mapper);
    issue(issuer, okKey, issueBody(holder, okKey, proof));

    String badKey = "tm-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    Map<String, Object> badBody = issueBody(holder, badKey, "not-a-proof");
    assertThatThrownBy(() -> issue(issuer, badKey, badBody))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);

    JsonNode own = summary(reader);
    JsonNode issue = own.get("stages").get("ISSUANCE_ISSUE");
    assertThat(issue).isNotNull();
    assertThat(issue.get("count").asLong()).isGreaterThanOrEqualTo(2);
    assertThat(issue.get("outcomes").get("OK").asLong()).isGreaterThanOrEqualTo(1);
    assertThat(issue.get("outcomes").get("REJECTED").asLong()).isGreaterThanOrEqualTo(1);
    assertThat(issue.get("maxMs").asLong()).isGreaterThanOrEqualTo(issue.get("p50Ms").asLong());

    boolean sawPermit = false;
    for (JsonNode reason : own.get("reasons")) {
      if ("ISSUE_CREDENTIAL".equals(reason.get("action").asString())
          && "PERMIT".equals(reason.get("decision").asString())) {
        sawPermit = true;
        assertThat(reason.get("count").asLong()).isGreaterThanOrEqualTo(1);
      }
    }
    assertThat(sawPermit).isTrue();

    // The failed validation is a REJECTED sample, never error text.
    String raw = mapper.writeValueAsString(own);
    assertThat(raw).doesNotContain("not-a-proof", "holder", "proof");

    JsonNode foreign = summary(outsider);
    assertThat(foreign.get("stages").has("ISSUANCE_ISSUE")).isFalse();
    for (JsonNode reason : foreign.get("reasons")) {
      assertThat(reason.get("action").asString()).isNotEqualTo("ISSUE_CREDENTIAL");
    }
  }
}
