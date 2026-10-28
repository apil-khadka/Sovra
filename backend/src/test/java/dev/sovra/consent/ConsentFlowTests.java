package dev.sovra.consent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
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
 * End-to-end consent: the RP opens a bound request, the holder reviews the
 * exact values and signs an explicit decision, and only approval delivers
 * an authorized presentation. Boots as the least-privilege role, like
 * production, so row-level security applies to every read below.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ConsentFlowTests extends SovraAppRoleBase {

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

  private record Stage(
      TestAccount issuer, TestAccount rp, TestAccount holderAgent,
      IssuanceFixtures.HolderKeys holder, String credentialId) {}

  private Stage stage(String tag) throws Exception {
    TestAccount issuer = TestAccounts.create(owner, tag + "-issuer", Set.of("ISSUER_OPS"));
    // One G1 synthetic tenant: the RP, the holder's agent, and the issued
    // credential all live under it. The agent carries transport
    // authentication; holder authority comes from the key proof.
    TestAccount rp = TestAccounts.createInTenant(
        owner, issuer.tenantId(), tag + "-rp", Set.of("RP_CLIENT"));
    TestAccount holderAgent = TestAccounts.createInTenant(
        owner, issuer.tenantId(), tag + "-agent", Set.of("TENANT_MEMBER"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String credentialId = ConsentFixtures.issueCredential(client, issuer, holder, mapper);
    return new Stage(issuer, rp, holderAgent, holder, credentialId);
  }

  @Test
  @SuppressWarnings("unchecked")
  void approveFlowDeliversSignedPresentation() throws Exception {
    Stage stage = stage("approve");
    Map<String, Object> created = ConsentFixtures.create(
        client, stage.rp(), ConsentFixtures.createBody(UUID.fromString(stage.credentialId())));
    assertThat(created).isNotNull();
    String requestId = created.get("requestId").toString();
    assertThat(created.get("state")).isEqualTo("PENDING");
    assertThat(((Number) created.get("trustSnapshot")).longValue()).isPositive();
    assertThat(created.get("holderThumbprint"))
        .isEqualTo(IssuanceFixtures.thumbprint(stage.holder()));

    Map<String, Object> review = ConsentFixtures.review(client, stage.rp(), requestId);
    assertThat(review.get("rpId")).isEqualTo(ConsentFixtures.RP_ID);
    assertThat(review.get("audience")).isEqualTo(ConsentFixtures.AUDIENCE);
    assertThat(review.get("purpose")).isEqualTo(ConsentFixtures.PURPOSE);
    assertThat(review.get("planHash")).isEqualTo(created.get("planHash"));
    assertThat(review.get("challenge")).isEqualTo(created.get("challenge"));
    assertThat(review.get("state")).isEqualTo("PENDING");

    Map<String, Object> decided = ConsentFixtures.decide(client, stage.holderAgent(), requestId,
        ConsentFixtures.decideBody(stage.holder(), review, "approve", mapper));
    assertThat(decided.get("state")).isEqualTo("VERIFIED");

    Map<String, Object> presentation = client
        .get()
        .uri("/api/consent/requests/" + requestId + "/presentation")
        .headers(stage.rp().headers())
        .retrieve()
        .body(Map.class);
    assertThat(presentation).isNotNull();
    assertThat(presentation.get("state")).isEqualTo("VERIFIED");
    assertThat(presentation.get("synthetic")).isEqualTo(Boolean.TRUE);
    assertThat(presentation.get("profile")).isEqualTo("sovra-g1-synthetic/0.2");
    ConsentFixtures.VerifiedPresentation verified = ConsentFixtures.verifyPresentation(
        presentation.get("presentation").toString(), stage.holder());
    assertThat(verified.payload()).isEqualTo(ConsentFixtures.consentMessage(review, "approve"));
    assertThat(presentation.get("claims").toString()).contains("adultOver18");

    Map<String, Object> audit =
        owner.queryForMap(
            "SELECT * FROM audit_event WHERE tenant_id = ? AND action = 'DECIDE_CONSENT'"
                + " ORDER BY occurred_at DESC LIMIT 1",
            stage.rp().tenantId());
    assertThat(audit.get("decision")).isEqualTo("PERMIT");
    assertThat(audit.get("detail").toString()).contains(requestId);
  }

  @Test
  void denyFlowLeavesNoPresentation() throws Exception {
    Stage stage = stage("deny");
    Map<String, Object> created = ConsentFixtures.create(
        client, stage.rp(), ConsentFixtures.createBody(UUID.fromString(stage.credentialId())));
    assertThat(created).isNotNull();
    String requestId = created.get("requestId").toString();

    Map<String, Object> review = ConsentFixtures.review(client, stage.rp(), requestId);
    Map<String, Object> decided = ConsentFixtures.decide(client, stage.holderAgent(), requestId,
        ConsentFixtures.decideBody(stage.holder(), review, "deny", mapper));
    assertThat(decided.get("state")).isEqualTo("DENIED");

    Map<String, Object> reread = ConsentFixtures.review(client, stage.rp(), requestId);
    assertThat(reread.get("state")).isEqualTo("DENIED");

    assertThatThrownBy(
            () ->
                client
                    .get()
                    .uri("/api/consent/requests/" + requestId + "/presentation")
                    .headers(stage.rp().headers())
                    .retrieve()
                    .body(String.class))
        .isInstanceOf(HttpClientErrorException.NotFound.class);

    Map<String, Object> audit =
        owner.queryForMap(
            "SELECT * FROM audit_event WHERE tenant_id = ? AND action = 'DECIDE_CONSENT'"
                + " ORDER BY occurred_at DESC LIMIT 1",
            stage.rp().tenantId());
    assertThat(audit.get("decision")).isEqualTo("PERMIT");
    assertThat(audit.get("detail").toString()).contains(requestId);
    assertThat(audit.get("detail").toString()).contains("deny");
  }

  @Test
  void reviewMatchesBoundRequestAndPresentedClaims() throws Exception {
    Stage stage = stage("exact");
    Map<String, Object> body =
        ConsentFixtures.createBody(UUID.fromString(stage.credentialId()));
    Map<String, Object> created = ConsentFixtures.create(client, stage.rp(), body);
    assertThat(created).isNotNull();
    String requestId = created.get("requestId").toString();

    // UX-01: the review shows exactly what creation bound.
    Map<String, Object> review = ConsentFixtures.review(client, stage.holderAgent(), requestId);
    assertThat(review.get("rpId")).isEqualTo(body.get("rpId"));
    assertThat(review.get("audience")).isEqualTo(body.get("audience"));
    assertThat(review.get("purpose")).isEqualTo(body.get("purpose"));
    assertThat(review.get("planHash")).isEqualTo(body.get("planHash"));
    assertThat(review.get("challenge")).isEqualTo(body.get("challenge"));
    assertThat(review.get("credentialId")).isEqualTo(stage.credentialId());
    assertThat(review.get("claims").toString()).contains("adultOver18");
    assertThat(review.get("expiresAt").toString()).isEqualTo(created.get("expiresAt").toString());

    ConsentFixtures.decide(client, stage.holderAgent(), requestId,
        ConsentFixtures.decideBody(stage.holder(), review, "approve", mapper));

    // What the holder reviewed is what the presentation carries.
    Map<String, Object> presentation = client
        .get()
        .uri("/api/consent/requests/" + requestId + "/presentation")
        .headers(stage.holderAgent().headers())
        .retrieve()
        .body(Map.class);
    assertThat(presentation).isNotNull();
    assertThat(presentation.get("claims").toString())
        .isEqualTo(review.get("claims").toString());
    assertThat(presentation.get("expiresAt").toString())
        .isEqualTo(review.get("expiresAt").toString());
  }
}
