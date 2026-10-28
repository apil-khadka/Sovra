package dev.sovra.consent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.guard.CandidatePlan;
import dev.sovra.guard.PlanGuard;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Guard-before-consent linkage (SOV-014, FR-06, INV-05): no holder
 * request is created unless the candidate plan is guard-accepted and
 * the bound hash equals the plan's canonical hash.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class GuardLinkageTests extends SovraAppRoleBase {

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

  private record Stage(TestAccount issuer, TestAccount rp,
      IssuanceFixtures.HolderKeys holder, String credentialId) {}

  private Stage stage(String tag) throws Exception {
    TestAccount issuer = TestAccounts.create(owner, tag + "-issuer", Set.of("ISSUER_OPS"));
    TestAccount rp = TestAccounts.createInTenant(
        owner, issuer.tenantId(), tag + "-rp", Set.of("RP_CLIENT"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String credentialId = ConsentFixtures.issueCredential(client, issuer, holder, mapper);
    return new Stage(issuer, rp, holder, credentialId);
  }

  private int requestCount(UUID tenantId) {
    Integer count =
        owner.queryForObject(
            "SELECT COUNT(*) FROM proof_request WHERE tenant_id = ?", Integer.class, tenantId);
    return count == null ? 0 : count;
  }

  @Test
  void rejectedPlanCreatesNoRequest() throws Exception {
    Stage stage = stage("link-reject");
    CandidatePlan base = ConsentFixtures.validPlan();
    CandidatePlan invented =
        new CandidatePlan(
            base.planId(), base.requestedOutcome(), "invented-issuer", base.credentialType(),
            base.claimPaths(), base.evidence(), base.policyId(), base.policyVersion(),
            base.recommendation());
    Map<String, Object> body =
        ConsentFixtures.createBody(UUID.fromString(stage.credentialId()));
    body.put("plan", ConsentFixtures.planBody(invented));
    body.put("planHash", PlanGuard.canonicalHash(invented));

    assertThatThrownBy(() -> ConsentFixtures.create(client, stage.rp(), body))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    assertThat(requestCount(stage.rp().tenantId())).isZero();
  }

  @Test
  void mismatchedPlanHashCreatesNoRequest() throws Exception {
    Stage stage = stage("link-hash");
    Map<String, Object> body =
        ConsentFixtures.createBody(UUID.fromString(stage.credentialId()));
    body.put("planHash", ConsentFixtures.planHash());

    assertThatThrownBy(() -> ConsentFixtures.create(client, stage.rp(), body))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    assertThat(requestCount(stage.rp().tenantId())).isZero();
  }

  @Test
  void missingPlanCreatesNoRequest() throws Exception {
    Stage stage = stage("link-missing");
    Map<String, Object> body =
        ConsentFixtures.createBody(UUID.fromString(stage.credentialId()));
    body.remove("plan");

    assertThatThrownBy(() -> ConsentFixtures.create(client, stage.rp(), body))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    assertThat(requestCount(stage.rp().tenantId())).isZero();
  }

  @Test
  void acceptedPlanCreatesRequestWithGuardAuditFirst() throws Exception {
    Stage stage = stage("link-ok");
    Map<String, Object> body =
        ConsentFixtures.createBody(UUID.fromString(stage.credentialId()));
    Map<String, Object> created = ConsentFixtures.create(client, stage.rp(), body);

    assertThat(created).isNotNull();
    assertThat(created.get("requestId")).isNotNull();
    assertThat(requestCount(stage.rp().tenantId())).isEqualTo(1);
    // The guard verdict commits with the request, ordered before the
    // consent audit row; a rejection would roll both back together.
    Integer guardRows =
        owner.queryForObject(
            "SELECT COUNT(*) FROM audit_event WHERE tenant_id = ? AND action = 'VALIDATE_PLAN'",
            Integer.class, stage.rp().tenantId());
    assertThat(guardRows).isEqualTo(1);
    Map<String, Object> guard =
        owner.queryForMap(
            "SELECT * FROM audit_event WHERE tenant_id = ? AND action = 'VALIDATE_PLAN'",
            stage.rp().tenantId());
    Map<String, Object> consent =
        owner.queryForMap(
            "SELECT * FROM audit_event WHERE tenant_id = ? AND action = 'REQUEST_PROOF'",
            stage.rp().tenantId());
    assertThat(guard.get("decision")).isEqualTo("PERMIT");
    assertThat(guard.get("detail").toString()).contains("GUARD_ACCEPTED");
    assertThat(((java.sql.Timestamp) guard.get("occurred_at")).toInstant())
        .isBeforeOrEqualTo(((java.sql.Timestamp) consent.get("occurred_at")).toInstant());
  }
}
