package dev.sovra.guard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.consent.ConsentFixtures;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import java.util.LinkedHashMap;
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
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Guard adjudication over live trust state (SOV-014, FR-06, SR-05):
 * validation runs before any holder request exists, rejects without
 * leaking trust internals, and audits a minimized verdict summary.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class GuardServiceTests extends SovraAppRoleBase {

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

  private Map<String, Object> validateBody(CandidatePlan plan, String policyId, String version) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("plan", ConsentFixtures.planBody(plan));
    body.put("policyId", policyId);
    body.put("policyVersion", version);
    return body;
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> validate(TestAccount caller, Map<String, Object> body) {
    return client
        .post()
        .uri("/api/guard/validate")
        .headers(caller.headers())
        .contentType(MediaType.APPLICATION_JSON)
        .body(body)
        .retrieve()
        .body(Map.class);
  }

  private Map<String, Object> lastVerdictAudit() {
    return owner.queryForMap(
        "SELECT * FROM audit_event WHERE action = 'VALIDATE_PLAN'"
            + " ORDER BY occurred_at DESC LIMIT 1");
  }

  @Test
  void livePlanIsAcceptedAndAudited() {
    TestAccount rp = TestAccounts.create(owner, "guard-rp", Set.of("RP_CLIENT"));
    CandidatePlan plan = ConsentFixtures.validPlan();
    Map<String, Object> verdict =
        validate(rp, validateBody(plan, GuardPolicies.POLICY_ID, GuardPolicies.POLICY_VERSION));

    assertThat(verdict).isNotNull();
    assertThat(verdict.get("accepted")).isEqualTo(Boolean.TRUE);
    assertThat(verdict.get("code")).isEqualTo("GUARD_ACCEPTED");
    assertThat(verdict.get("rulesVersion")).isEqualTo(PlanGuard.RULES_VERSION);
    assertThat(((Number) verdict.get("snapshotVersion")).longValue()).isPositive();

    Map<String, Object> audit = lastVerdictAudit();
    assertThat(audit.get("decision")).isEqualTo("PERMIT");
    assertThat(audit.get("detail").toString()).contains("GUARD_ACCEPTED");
  }

  @Test
  void inventedIssuerRejectsWithoutLeakingTrust() {
    TestAccount rp = TestAccounts.create(owner, "guard-invent", Set.of("RP_CLIENT"));
    CandidatePlan base = ConsentFixtures.validPlan();
    CandidatePlan invented =
        new CandidatePlan(
            base.planId(), base.requestedOutcome(), "invented-issuer", base.credentialType(),
            base.claimPaths(), base.evidence(), base.policyId(), base.policyVersion(),
            base.recommendation());
    Map<String, Object> verdict =
        validate(rp, validateBody(invented, GuardPolicies.POLICY_ID, GuardPolicies.POLICY_VERSION));

    assertThat(verdict).isNotNull();
    assertThat(verdict.get("accepted")).isEqualTo(Boolean.FALSE);
    assertThat(verdict.get("code")).isEqualTo("GUARD_UNKNOWN_ISSUER");

    // Minimized audit: verdict summary only, no plan content or claims.
    Map<String, Object> audit = lastVerdictAudit();
    assertThat(audit.get("decision")).isEqualTo("PERMIT");
    String detail = audit.get("detail").toString();
    assertThat(detail).contains("GUARD_UNKNOWN_ISSUER");
    assertThat(detail).doesNotContain("invented-issuer", "adultOver18");
  }

  @Test
  void malformedEnvelopesAreRejected() {
    TestAccount rp = TestAccounts.create(owner, "guard-bad", Set.of("RP_CLIENT"));
    assertThatThrownBy(() -> validate(rp, Map.of("policyId", "x", "policyVersion", "1")))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);

    Map<String, Object> badSchema = new LinkedHashMap<>();
    Map<String, Object> plan = new LinkedHashMap<>(ConsentFixtures.planBody(ConsentFixtures.validPlan()));
    plan.put("recommendation", "AUTO_APPROVE");
    badSchema.put("plan", plan);
    badSchema.put("policyId", GuardPolicies.POLICY_ID);
    badSchema.put("policyVersion", GuardPolicies.POLICY_VERSION);
    assertThatThrownBy(() -> validate(rp, badSchema))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void wrongRolesAreDeniedAndAudited() {
    TestAccount admin = TestAccounts.create(owner, "guard-admin", Set.of("TRUST_ADMIN"));
    Map<String, Object> body =
        validateBody(ConsentFixtures.validPlan(), GuardPolicies.POLICY_ID,
            GuardPolicies.POLICY_VERSION);
    assertThatThrownBy(() -> validate(admin, body))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    Map<String, Object> audit = lastVerdictAudit();
    assertThat(audit.get("decision")).isEqualTo("DENY");
  }

  @Test
  void anonymousCallsAreRejected() {
    Map<String, Object> body =
        validateBody(ConsentFixtures.validPlan(), GuardPolicies.POLICY_ID,
            GuardPolicies.POLICY_VERSION);
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/guard/validate")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body)
                    .retrieve()
                    .body(String.class))
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
  }

  @Test
  void missingSnapshotIsUnavailable() {
    TestAccount rp = TestAccounts.create(owner, "guard-nosnap", Set.of("RP_CLIENT"));
    Long version =
        owner.queryForObject("SELECT MAX(snapshot_version) FROM trust_snapshot_activation",
            Long.class);
    assertThat(version).isNotNull();
    owner.update("DELETE FROM trust_snapshot_activation");
    try {
      Map<String, Object> body =
          validateBody(ConsentFixtures.validPlan(), GuardPolicies.POLICY_ID,
              GuardPolicies.POLICY_VERSION);
      assertThatThrownBy(() -> validate(rp, body))
          .isInstanceOf(HttpServerErrorException.ServiceUnavailable.class);
    } finally {
      owner.update(
          "INSERT INTO trust_snapshot_activation (snapshot_version, activated_by)"
              + " VALUES (?, 'test-restore')",
          version);
    }
  }
}
