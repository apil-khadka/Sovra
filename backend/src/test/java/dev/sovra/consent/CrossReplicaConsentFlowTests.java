package dev.sovra.consent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.SovraApplication;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import dev.sovra.verification.VerificationFixtures;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Consent-to-verification across replicas (PROD-015). Machine APIs
 * keep no flow state in memory: a request created on A is decided
 * and verified on B, a replica restart loses nothing, and the peer
 * re-validates every proof instead of trusting its sibling.
 * Accreditation decisions travel the same way.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
    properties = {"server.port=18090"})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class CrossReplicaConsentFlowTests extends SovraAppRoleBase {

  static final String BASE_A = "http://localhost:18090";
  static final String BASE_B = "http://localhost:18091";

  /** Second replica: same code, same database, separate memory and port. */
  static ConfigurableApplicationContext replica;

  @BeforeAll
  static void startReplica() {
    replica = replicaBuilder().run();
  }

  @AfterAll
  static void stopReplica() {
    if (replica != null) {
      replica.close();
    }
  }

  private static SpringApplicationBuilder replicaBuilder() {
    return new SpringApplicationBuilder(SovraApplication.class)
        .initializers(
            (org.springframework.context.ApplicationContextInitializer<
                    org.springframework.context.ConfigurableApplicationContext>)
                context ->
                    org.springframework.test.context.support.TestPropertySourceUtils
                        .addInlinedPropertiesToEnvironment(
                            context,
                            "server.port=18091",
                            "spring.datasource.url=" + containerJdbcUrl(),
                            "spring.datasource.username=" + appRoleName(),
                            "spring.datasource.password=" + appRolePassword(),
                            "spring.flyway.user=" + containerUsername(),
                            "spring.flyway.password=" + containerPassword()));
  }

  @Autowired TrustService trust;

  @Autowired ObjectMapper mapper;

  JdbcTemplate owner;
  RestClient a;
  RestClient b;

  @BeforeEach
  void setup() throws Exception {
    owner = new JdbcTemplate(ownerDataSource());
    IssuanceFixtures.ensureSyntheticIssuer(owner, trust, mapper);
    a = RestClient.builder().baseUrl(BASE_A).build();
    b = RestClient.builder().baseUrl(BASE_B).build();
  }

  @Test
  void createdOnADecidedAndVerifiedOnB() throws Exception {
    Flow flow = Flow.create(owner, mapper, "xflow");
    String credentialId =
        ConsentFixtures.issueCredential(a, flow.issuer(), flow.holder(), mapper);
    // Create on A, review and decide on B.
    Map<String, Object> created = ConsentFixtures.create(
        a, flow.rp(), ConsentFixtures.createBody(UUID.fromString(credentialId)));
    String requestId = created.get("requestId").toString();
    Map<String, Object> review = ConsentFixtures.review(b, flow.rp(), requestId);
    assertThat(review.get("requestId").toString()).isEqualTo(requestId);
    ConsentFixtures.decide(
        b, flow.agent(), requestId,
        ConsentFixtures.decideBody(flow.holder(), review, "approve", mapper));
    // Verify on B: the peer needs nothing from A's memory.
    Map<String, Object> decided = VerificationFixtures.verify(
        b, flow.rp(),
        VerificationFixtures.verifyBody(
            flow.holder(), requestId, VerificationFixtures.nonce(),
            ConsentFixtures.AUDIENCE, mapper));
    assertThat(decided.get("outcome")).isEqualTo("ACCEPTED");
  }

  @Test
  void replicaRestartLosesNoFlowState() throws Exception {
    Flow flow = Flow.create(owner, mapper, "xrestart");
    String credentialId =
        ConsentFixtures.issueCredential(a, flow.issuer(), flow.holder(), mapper);
    Map<String, Object> created = ConsentFixtures.create(
        a, flow.rp(), ConsentFixtures.createBody(UUID.fromString(credentialId)));
    String requestId = created.get("requestId").toString();
    // Restart the peer mid-flow: fresh JVM memory, same database.
    replica.close();
    replica = replicaBuilder().run();
    Map<String, Object> review = ConsentFixtures.review(b, flow.rp(), requestId);
    ConsentFixtures.decide(
        b, flow.agent(), requestId,
        ConsentFixtures.decideBody(flow.holder(), review, "approve", mapper));
    Map<String, Object> decided = VerificationFixtures.verify(
        b, flow.rp(),
        VerificationFixtures.verifyBody(
            flow.holder(), requestId, VerificationFixtures.nonce(),
            ConsentFixtures.AUDIENCE, mapper));
    assertThat(decided.get("outcome")).isEqualTo("ACCEPTED");
  }

  @Test
  void peerRevalidatesEveryProof() throws Exception {
    Flow flow = Flow.create(owner, mapper, "xtamper");
    String credentialId =
        ConsentFixtures.issueCredential(a, flow.issuer(), flow.holder(), mapper);
    Map<String, Object> created = ConsentFixtures.create(
        a, flow.rp(), ConsentFixtures.createBody(UUID.fromString(credentialId)));
    String requestId = created.get("requestId").toString();
    // A decision proof from the wrong holder fails on the peer.
    IssuanceFixtures.HolderKeys impostor = IssuanceFixtures.generateHolder(mapper);
    Map<String, Object> review = ConsentFixtures.review(b, flow.rp(), requestId);
    assertThatThrownBy(() -> ConsentFixtures.decide(
            b, flow.agent(), requestId,
            ConsentFixtures.decideBody(impostor, review, "approve", mapper)))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    // So does a presentation under the wrong key after approval.
    ConsentFixtures.decide(
        b, flow.agent(), requestId,
        ConsentFixtures.decideBody(flow.holder(), review, "approve", mapper));
    Map<String, Object> rejected = VerificationFixtures.verify(
        b, flow.rp(),
        VerificationFixtures.verifyBody(
            impostor, requestId, VerificationFixtures.nonce(),
            ConsentFixtures.AUDIENCE, mapper));
    assertThat(rejected)
        .containsEntry("outcome", "REJECTED")
        .containsEntry("reasonCode", "HOLDER_MISMATCH");
  }

  @Test
  @SuppressWarnings("unchecked")
  void accreditationDecidedAcrossReplicas() throws Exception {
    TestAccount member = TestAccounts.create(owner, "xacc-member", Set.of("TENANT_MEMBER"));
    TestAccount admin = TestAccounts.createInTenant(
        owner, member.tenantId(), "xacc-admin", Set.of("TRUST_ADMIN"));
    // Request on A, approve on B, use on A, revoke on B.
    Map<String, Object> requested = a.post().uri("/api/accreditations")
        .headers(member.headers())
        .body(Map.of(
            "orgName", "Replica Shop",
            "roles", List.of("RP_CLIENT"),
            "origins", List.of("https://shop.example"),
            "audiences", List.of(ConsentFixtures.AUDIENCE)))
        .retrieve()
        .body(Map.class);
    String accreditationId = requested.get("accreditationId").toString();
    Map<String, Object> approved = b.post().uri("/api/accreditations/" + accreditationId + "/approve")
        .headers(admin.headers())
        .body(Map.of())
        .retrieve()
        .body(Map.class);
    assertThat(approved.get("state")).isEqualTo("APPROVED");
    String token = approved.get("oneTimeToken").toString();
    Flow flow = Flow.createIn(owner, mapper, member.tenantId(), "xacc-use");
    String credentialId =
        ConsentFixtures.issueCredential(a, flow.issuer(), flow.holder(), mapper);
    Map<String, Object> created = a.post().uri("/api/consent/requests")
        .headers(headers -> headers.setBearerAuth(token))
        .body(ConsentFixtures.createBody(UUID.fromString(credentialId)))
        .retrieve()
        .body(Map.class);
    assertThat(created.get("requestId")).isNotNull();
    // Revocation on B kills the bearer on A immediately.
    b.post().uri("/api/accreditations/" + accreditationId + "/revoke")
        .headers(admin.headers())
        .retrieve()
        .toBodilessEntity();
    assertThatThrownBy(() -> a.post().uri("/api/consent/requests")
            .headers(headers -> headers.setBearerAuth(token))
            .body(ConsentFixtures.createBody(UUID.fromString(credentialId)))
            .retrieve()
            .body(Map.class))
        .isInstanceOf(HttpClientErrorException.class);
  }

  private record Flow(
      TestAccount issuer, TestAccount rp, TestAccount agent, IssuanceFixtures.HolderKeys holder) {
    static Flow create(JdbcTemplate owner, ObjectMapper mapper, String tag) throws Exception {
      TestAccount issuer = TestAccounts.create(owner, tag + "-issuer", Set.of("ISSUER_OPS"));
      return createIn(owner, mapper, issuer.tenantId(), tag);
    }

    static Flow createIn(JdbcTemplate owner, ObjectMapper mapper, UUID tenantId, String tag)
        throws Exception {
      TestAccount issuer = TestAccounts.createInTenant(
          owner, tenantId, tag + "-issuer", Set.of("ISSUER_OPS"));
      TestAccount rp = TestAccounts.createInTenant(
          owner, tenantId, tag + "-rp", Set.of("RP_CLIENT"));
      TestAccount agent = TestAccounts.createInTenant(
          owner, tenantId, tag + "-agent", Set.of("TENANT_MEMBER"));
      return new Flow(issuer, rp, agent, IssuanceFixtures.generateHolder(mapper));
    }
  }
}
