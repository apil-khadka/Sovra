package dev.sovra.planning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Live-path failure closure (SOV-013, FR-12, FR-29, SEC-19, IF-04): when
 * live planning is armed but the provider is unreachable, proposals
 * fail explicitly as unavailable — retryable, audited as nothing, and
 * never silently downgraded to the fixture planner.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {
      "sovra.ai.live-enabled=true",
      "sovra.ai.base-url=http://127.0.0.1:9",
      "sovra.ai.api-key=test-only-unreachable-key",
      "sovra.ai.model=test-only-unreachable-model",
      "sovra.ai.timeout=2s",
      "sovra.ai.max-retries=0"
    })
class PlanningLiveFailureTests extends SovraAppRoleBase {

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

  @Test
  void unreachableProviderFailsExplicitlyWithoutFixtureFallback() {
    TestAccount rp = TestAccounts.create(owner, "plan-live-rp", Set.of("RP_CLIENT"));
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/plans/propose")
                    .headers(rp.headers())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(PlanningModeTests.intentBody())
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOfSatisfying(
            HttpServerErrorException.ServiceUnavailable.class,
            e -> {
              assertThat(e.getResponseBodyAsString()).contains("planning_unavailable");
              assertThat(e.getResponseBodyAsString()).doesNotContain("FIXTURE", "plan_id");
            });
  }

  @Test
  void outageProblemIsRetryable() throws Exception {
    TestAccount rp = TestAccounts.create(owner, "plan-live-rp2", Set.of("RP_CLIENT"));
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/plans/propose")
                    .headers(rp.headers())
                    .accept(MediaType.parseMediaType("application/problem+json"))
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(PlanningModeTests.intentBody())
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOfSatisfying(
            HttpServerErrorException.ServiceUnavailable.class,
            e -> {
              @SuppressWarnings("unchecked")
              Map<String, Object> problem =
                  mapper.readValue(e.getResponseBodyAsString(), Map.class);
              assertThat(problem.get("code")).isEqualTo("dependency_unavailable");
              assertThat(problem.get("retryable")).isEqualTo(Boolean.TRUE);
            });
  }

  @Test
  @SuppressWarnings("unchecked")
  void statusReportsArmedLiveHonestly() {
    TestAccount member = TestAccounts.create(owner, "plan-live-member", Set.of("TENANT_MEMBER"));
    Map<String, Object> status =
        client
            .get()
            .uri("/api/plans/status")
            .headers(member.headers())
            .retrieve()
            .body(Map.class);

    assertThat(status).isNotNull();
    assertThat(status.get("mode")).isEqualTo("LIVE");
    assertThat(status.get("liveEnabled")).isEqualTo(Boolean.TRUE);
    assertThat(status.get("modelConfigured")).isEqualTo(Boolean.TRUE);
  }
}
