package dev.sovra.planning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.guard.GuardPolicies;
import dev.sovra.guard.PlanParser;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
import tools.jackson.databind.ObjectMapper;

/**
 * Planning modes over HTTP (SOV-013, FR-04, FR-05, FR-29): default
 * boot serves explicitly-labeled fixture candidates, invalid intents
 * fail before any model contact, anonymous and wrong-role callers are
 * refused with audited denials, and status distinguishes fixture from
 * live readiness without exposing secrets.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class PlanningModeTests extends SovraAppRoleBase {

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

  static Map<String, Object> intentBody() {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("rpId", "https://rp.example/synth-shop");
    body.put("audience", "https://rp.example/synth-shop/callback");
    body.put("purpose", "synthetic age check at checkout");
    body.put("outcome", "age_over_18");
    body.put("policyId", GuardPolicies.POLICY_ID);
    body.put("policyVersion", GuardPolicies.POLICY_VERSION);
    body.put("requestedClaims", List.of("adultOver18"));
    return body;
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> propose(TestAccount caller, Map<String, Object> body) {
    return client
        .post()
        .uri("/api/plans/propose")
        .headers(caller.headers())
        .contentType(MediaType.APPLICATION_JSON)
        .body(body)
        .retrieve()
        .body(Map.class);
  }

  @Test
  void defaultBootServesLabeledFixtureCandidates() throws Exception {
    TestAccount rp = TestAccounts.create(owner, "plan-rp", Set.of("RP_CLIENT"));
    Map<String, Object> result = propose(rp, intentBody());

    assertThat(result).isNotNull();
    assertThat(result.get("mode")).isEqualTo("FIXTURE");
    assertThat(result.get("liveAcceptance")).isEqualTo(Boolean.FALSE);
    assertThat(result.get("synthetic")).isEqualTo(Boolean.TRUE);
    assertThat(result.get("recommendation")).isEqualTo("CANDIDATE_ONLY");
    assertThat(result.get("model")).isEqualTo("none (fixture)");
    assertThat(result.get("promptVersion")).isEqualTo(PlanningVersions.PROMPT_VERSION);
    assertThat(result.get("toolContractVersion")).isEqualTo(PlanningVersions.TOOL_CONTRACT_VERSION);
    assertThat(result.get("toolSchemaHash").toString()).matches("[0-9a-f]{64}");
    assertThat(result.get("cost")).isEqualTo("unreported");
    assertThat(((Number) result.get("snapshotVersion")).longValue()).isPositive();

    // Wire-shape compatibility: the fixture plan parses as a guard plan.
    @SuppressWarnings("unchecked")
    Map<String, Object> wire = (Map<String, Object>) result.get("plan");
    assertThat(wire).isNotNull();
    String json = mapper.writeValueAsString(wire);
    var plan = PlanParser.parsePlan(mapper.readTree(json));
    assertThat(plan.candidateIssuerId()).isEqualTo(IssuanceFixtures.ISSUER_ID);
    assertThat(plan.recommendation().name()).isEqualTo("CANDIDATE_ONLY");

    Map<String, Object> audit =
        owner.queryForMap(
            "SELECT * FROM audit_event WHERE action = 'PROPOSE_PLAN' AND tenant_id = ?"
                + " ORDER BY occurred_at DESC LIMIT 1",
            rp.tenantId());
    assertThat(audit.get("decision")).isEqualTo("PERMIT");
    String detail = audit.get("detail").toString();
    assertThat(detail).contains("FIXTURE", "CANDIDATE_ONLY", "liveAcceptance");
    assertThat(detail).doesNotContain("synth-shop", "adultOver18");
  }

  @Test
  void invalidIntentsFailBeforeAnyModelContact() {
    TestAccount rp = TestAccounts.create(owner, "plan-invalid", Set.of("RP_CLIENT"));
    Map<String, Object> badOutcome = intentBody();
    badOutcome.put("outcome", "age_over_21");
    assertThatThrownBy(() -> propose(rp, badOutcome))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);

    Map<String, Object> badClaim = intentBody();
    badClaim.put("requestedClaims", List.of("passportNumber"));
    assertThatThrownBy(() -> propose(rp, badClaim))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);

    Map<String, Object> badPolicy = intentBody();
    badPolicy.put("policyId", "rp-custom-policy/unreviewed");
    assertThatThrownBy(() -> propose(rp, badPolicy))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);

    Map<String, Object> missing = intentBody();
    missing.remove("purpose");
    assertThatThrownBy(() -> propose(rp, missing))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void anonymousAndWrongRoleCallersAreRefused() {
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/plans/propose")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(intentBody())
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);

    TestAccount issuer = TestAccounts.create(owner, "plan-issuer", Set.of("ISSUER_OPS"));
    assertThatThrownBy(() -> propose(issuer, intentBody()))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);

    Map<String, Object> audit =
        owner.queryForMap(
            "SELECT * FROM audit_event WHERE action = 'PROPOSE_PLAN' AND tenant_id = ?"
                + " ORDER BY occurred_at DESC LIMIT 1",
            issuer.tenantId());
    assertThat(audit.get("decision")).isEqualTo("DENY");
  }

  @Test
  @SuppressWarnings("unchecked")
  void statusDistinguishesFixtureFromLiveWithoutSecrets() {
    TestAccount member = TestAccounts.create(owner, "plan-member", Set.of("TENANT_MEMBER"));
    Map<String, Object> status =
        client
            .get()
            .uri("/api/plans/status")
            .headers(member.headers())
            .retrieve()
            .body(Map.class);

    assertThat(status).isNotNull();
    assertThat(status.get("mode")).isEqualTo("FIXTURE");
    assertThat(status.get("liveEnabled")).isEqualTo(Boolean.FALSE);
    assertThat(status.get("modelConfigured")).isEqualTo(Boolean.FALSE);
    assertThat(status.get("promptVersion")).isEqualTo(PlanningVersions.PROMPT_VERSION);
    assertThat(status.get("baselineVersion")).isEqualTo(PlanningVersions.BASELINE_VERSION);
    assertThat((List<String>) status.get("tools"))
        .containsExactlyInAnyOrder(
            "listTrustedIssuers",
            "getCredentialSchema",
            "getPolicyDocument",
            "getIssuerCapabilities",
            "compareEvidence");
  }
}
