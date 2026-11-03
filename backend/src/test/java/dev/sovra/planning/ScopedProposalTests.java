package dev.sovra.planning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.guard.ApprovedSchemas;
import dev.sovra.guard.GuardPolicies;
import dev.sovra.issuance.DualIssuerFixtures;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.issuance.LocalDevSigner;
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
 * Scoped discovery over HTTP in fixture mode: the canonical hint plus a
 * narrowing scope drives adaptation (synth-2 scoped pick discovers the
 * fjord wire pair) and genuine refusal (employment scope yields NO_PATH,
 * never 400); status exposes capabilities without model calls.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ScopedProposalTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  @Autowired TrustService trust;

  @Autowired ObjectMapper mapper;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() throws Exception {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
    DualIssuerFixtures.ensureDualIssuers(owner, trust, mapper);
  }

  private Map<String, Object> intentBody(
      String policyId, List<String> claims, Map<String, Object> scope) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("rpId", "https://rp.example/synth-shop");
    body.put("audience", "https://rp.example/synth-shop/callback");
    body.put("purpose", "synthetic age check at checkout");
    body.put("outcome", "age_over_18");
    body.put("policyId", policyId);
    body.put("policyVersion", "1");
    body.put("requestedClaims", claims);
    if (scope != null) {
      body.putAll(scope);
    }
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
  @SuppressWarnings("unchecked")
  void scopedPickDiscoversFjordWirePair() {
    TestAccount rp = TestAccounts.create(owner, "scope-fjord", Set.of("RP_CLIENT"));
    Map<String, Object> result = propose(
        rp,
        intentBody(
            GuardPolicies.MAPPED_POLICY_ID,
            List.of("adultOver18"),
            Map.of("scopeIssuerIds", List.of(LocalDevSigner.SECOND_ISSUER_ID))));
    assertThat(result.get("recommendation")).isEqualTo("CANDIDATE_ONLY");
    Map<String, Object> plan = (Map<String, Object>) result.get("plan");
    assertThat(plan.get("candidate_issuer_id")).isEqualTo(LocalDevSigner.SECOND_ISSUER_ID);
    assertThat(plan.get("credential_type")).isEqualTo(ApprovedSchemas.FJORD_VCT);
    assertThat(plan.get("claim_paths")).isEqualTo(List.of("isAdult"));
    // Scope echo for UI verification.
    assertThat(result.get("scopeIssuerIds"))
        .isEqualTo(List.of(LocalDevSigner.SECOND_ISSUER_ID));
  }

  @Test
  void employmentScopeYieldsNoPathInsteadOf400() {
    TestAccount rp = TestAccounts.create(owner, "scope-tenure", Set.of("RP_CLIENT"));
    Map<String, Object> scope = new LinkedHashMap<>();
    scope.put("scopeIssuerIds", List.of(LocalDevSigner.SECOND_ISSUER_ID));
    scope.put("scopeCredentialTypes", List.of(ApprovedSchemas.EMPLOYMENT_VCT));
    Map<String, Object> result = propose(
        rp, intentBody(GuardPolicies.MAPPED_POLICY_ID, List.of("adultOver18"), scope));
    // An ACTUAL proposal outcome after discovery, not validation failure.
    assertThat(result.get("recommendation")).isEqualTo("NO_PATH");
    assertThat(result.get("plan")).isNull();
  }

  @Test
  void unknownScopeYieldsNoPathInsteadOf400() {
    TestAccount rp = TestAccounts.create(owner, "scope-unknown", Set.of("RP_CLIENT"));
    Map<String, Object> result = propose(
        rp,
        intentBody(
            GuardPolicies.MAPPED_POLICY_ID,
            List.of("adultOver18"),
            Map.of("scopeIssuerIds",
                List.of("https://sovra.example/issuers/retired-9"))));
    assertThat(result.get("recommendation")).isEqualTo("NO_PATH");
    assertThat(result.get("plan")).isNull();
  }

  @Test
  void unscopedLegacyFlowIsUnchanged() {
    TestAccount rp = TestAccounts.create(owner, "scope-legacy", Set.of("RP_CLIENT"));
    Map<String, Object> result = propose(
        rp, intentBody(GuardPolicies.POLICY_ID, List.of("adultOver18"), null));
    assertThat(result.get("recommendation")).isEqualTo("CANDIDATE_ONLY");
    assertThat(result.get("scopeIssuerIds")).isEqualTo(List.of());
    assertThat(result.get("scopeCredentialTypes")).isEqualTo(List.of());
    assertThat(result.get("scopeJurisdictions")).isEqualTo(List.of());
  }

  @Test
  void guessedNestedScopeShapeIsRejected() {
    TestAccount rp = TestAccounts.create(owner, "scope-guessed", Set.of("RP_CLIENT"));
    Map<String, Object> body = intentBody(
        GuardPolicies.MAPPED_POLICY_ID, List.of("adultOver18"), null);
    body.put("discoveryScope", Map.of("issuerIds", List.of("x")));
    assertThatThrownBy(() -> propose(rp, body))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    Map<String, Object> empty = intentBody(
        GuardPolicies.MAPPED_POLICY_ID, List.of(), null);
    assertThatThrownBy(() -> propose(rp, empty))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  @SuppressWarnings("unchecked")
  void statusExposesCapabilitiesWithoutModelCalls() {
    TestAccount member = TestAccounts.create(owner, "scope-status", Set.of("TENANT_MEMBER"));
    Map<String, Object> status =
        client
            .get()
            .uri("/api/plans/status")
            .headers(member.headers())
            .retrieve()
            .body(Map.class);
    assertThat(status).isNotNull();
    assertThat(status.get("discoveryScopeSupported")).isEqualTo(Boolean.TRUE);
    assertThat(status.get("schemaRegistryVersion"))
        .isEqualTo(ApprovedSchemas.version());
    assertThat(status.get("guardRulesVersion"))
        .isEqualTo(dev.sovra.guard.PlanGuard.RULES_VERSION);
    List<Map<String, String>> bindings =
        (List<Map<String, String>>) status.get("supportedPolicyBindings");
    assertThat(bindings).hasSize(2);
    assertThat(bindings.stream().map(b -> b.get("policyId")).toList())
        .containsExactlyInAnyOrder(
            GuardPolicies.POLICY_ID, GuardPolicies.MAPPED_POLICY_ID);
    // Old fields stay compatible.
    assertThat(status.get("promptVersion")).isEqualTo(PlanningVersions.PROMPT_VERSION);
    assertThat(status.get("toolSchemaHash").toString()).matches("[0-9a-f]{64}");
  }

  @Test
  void scopedAuditRecordsScopedFlagWithoutValues() {
    TestAccount rp = TestAccounts.create(owner, "scope-audit", Set.of("RP_CLIENT"));
    propose(
        rp,
        intentBody(
            GuardPolicies.MAPPED_POLICY_ID,
            List.of("adultOver18"),
            Map.of("scopeIssuerIds", List.of(LocalDevSigner.SECOND_ISSUER_ID))));
    Map<String, Object> audit = owner.queryForMap(
        "SELECT * FROM audit_event WHERE action = 'PROPOSE_PLAN' AND tenant_id = ?"
            + " ORDER BY occurred_at DESC LIMIT 1",
        rp.tenantId());
    assertThat(audit.get("detail").toString()).contains("scoped");
  }
}
