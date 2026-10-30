package dev.sovra.bff;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.consent.ConsentFixtures;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import dev.sovra.verification.VerificationFixtures;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Session-chain holder journey (SOV-006, SOV-041 browser path):
 * review, holder-signed decide, presentation, verification submit,
 * and decision read over BFF sessions — the same services the
 * machine chain serves, with identical authority checks. Shares the
 * application context with {@code BffLoginTests} (identical test
 * configuration).
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
    properties = {
      "server.port=18083",
      "sovra.bff.enabled=true",
      "sovra.bff.require-https-issuer=false",
      "sovra.bff.redirect-uri=http://localhost:18083/login/oauth2/code/sovra",
      "sovra.bff.post-logout-redirect-uri=http://localhost:18083/",
      "spring.security.oauth2.client.registration.sovra.client-id=sovra-bff",
      "spring.security.oauth2.client.registration.sovra.client-secret=stub-secret",
      "spring.security.oauth2.client.registration.sovra.scope=openid,profile,groups,tenant",
      "spring.security.oauth2.client.registration.sovra.redirect-uri=http://localhost:18083/login/oauth2/code/sovra"
    })
// Frees this fixed-port context (and its JDBC pool) after the class: with six such
// contexts the shared test Postgres runs out of connection slots otherwise.
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class BffHolderFlowTests extends SovraAppRoleBase {

  static final String BASE = "http://localhost:18083";
  static final StubOpenIdProvider STUB;

  static {
    try {
      STUB = new StubOpenIdProvider("sovra-bff", "stub-secret");
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  @DynamicPropertySource
  static void stubProvider(DynamicPropertyRegistry registry) {
    registry.add(
        "spring.security.oauth2.client.provider.sovra.issuer-uri", STUB::issuer);
    registry.add("sovra.bff.issuer", STUB::issuer);
    registry.add("sovra.bff.end-session-endpoint", () -> STUB.baseUrl() + "/stub-logout");
  }

  @AfterAll
  static void closeStub() {
    STUB.close();
  }

  @Autowired TrustService trust;

  @Autowired ObjectMapper mapper;

  RestClient client;
  JdbcTemplate owner;
  HttpClient http;

  @BeforeEach
  void setup() throws Exception {
    client = RestClient.builder().baseUrl(BASE).build();
    owner = new JdbcTemplate(ownerDataSource());
    owner.update(
        "INSERT INTO tenant (slug, display_name) VALUES ('sovra-demo', 'BFF demo')"
            + " ON CONFLICT (slug) DO NOTHING");
    IssuanceFixtures.ensureSyntheticIssuer(owner, trust, mapper);
    http = HttpClient.newBuilder().followRedirects(Redirect.NEVER).build();
  }

  record Prepared(TestAccount issuer, TestAccount rp, IssuanceFixtures.HolderKeys holder,
      String credentialId, String requestId, Map<String, Object> review) {}

  private Prepared prepare(String tag) throws Exception {
    UUID tenant = owner.queryForObject(
        "SELECT id FROM tenant WHERE slug = 'sovra-demo'", UUID.class);
    TestAccount issuer =
        TestAccounts.createInTenant(owner, tenant, tag + "-issuer", Set.of("ISSUER_OPS"));
    TestAccount rp =
        TestAccounts.createInTenant(owner, tenant, tag + "-rp", Set.of("RP_CLIENT"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String credentialId = ConsentFixtures.issueCredential(client, issuer, holder, mapper);
    Map<String, Object> created =
        ConsentFixtures.create(client, rp, ConsentFixtures.createBody(UUID.fromString(credentialId)));
    String requestId = created.get("requestId").toString();
    Map<String, Object> review = ConsentFixtures.review(client, rp, requestId);
    return new Prepared(issuer, rp, holder, credentialId, requestId, review);
  }

  private BffTestSessions.Session login(List<String> groups) throws Exception {
    String subject = "holder-" + UUID.randomUUID().toString().substring(0, 8);
    return BffTestSessions.login(
        http, mapper, BASE, STUB,
        new StubOpenIdProvider.Script(subject, groups, "sovra-demo", List.of()));
  }

  private HttpResponse<String> postJson(
      String path, BffTestSessions.Session session, Map<String, Object> body) throws Exception {
    HttpRequest request = HttpRequest.newBuilder(URI.create(BASE + path))
        .timeout(Duration.ofSeconds(30))
        .header("Cookie", "JSESSIONID=" + session.jsessionid() + "; XSRF-TOKEN=" + session.xsrf())
        .header("X-XSRF-TOKEN", session.xsrf())
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
        .build();
    return http.send(request, HttpResponse.BodyHandlers.ofString());
  }

  private HttpResponse<String> sessionGet(String path, BffTestSessions.Session session,
      Map<String, String> extra) throws Exception {
    Map<String, String> headers = new java.util.HashMap<>(extra);
    headers.put("Cookie", "JSESSIONID=" + session.jsessionid());
    return BffTestSessions.get(http, BASE + path, headers);
  }

  @Test
  void sessionHolderJourneyEndToEnd() throws Exception {
    Prepared stage = prepare("bffj");
    BffTestSessions.Session session = login(List.of("sovra-members", "sovra-rp"));

    HttpResponse<String> review =
        sessionGet("/api/bff/consent/requests/" + stage.requestId(), session, Map.of());
    assertThat(review.statusCode()).isEqualTo(200);
    String etag = review.headers().firstValue("etag").orElse("");
    assertThat(etag).isNotBlank();
    assertThat(mapper.readTree(review.body()).get("state").asString()).isEqualTo("PENDING");
    HttpResponse<String> cached = sessionGet(
        "/api/bff/consent/requests/" + stage.requestId(), session, Map.of("If-None-Match", etag));
    assertThat(cached.statusCode()).isEqualTo(304);

    Map<String, Object> decideBody =
        ConsentFixtures.decideBody(stage.holder(), stage.review(), "approve", mapper);
    HttpResponse<String> decided =
        postJson("/api/bff/consent/requests/" + stage.requestId() + "/decision", session, decideBody);
    assertThat(decided.statusCode()).isEqualTo(200);
    assertThat(mapper.readTree(decided.body()).get("state").asString()).isEqualTo("VERIFIED");

    HttpResponse<String> presentation = sessionGet(
        "/api/bff/consent/requests/" + stage.requestId() + "/presentation", session, Map.of());
    assertThat(presentation.statusCode()).isEqualTo(200);

    Map<String, Object> submission = VerificationFixtures.verifyBody(stage.holder(),
        stage.requestId(), VerificationFixtures.nonce(), ConsentFixtures.AUDIENCE, mapper);
    HttpResponse<String> verdict =
        postJson("/api/bff/verification/presentations", session, submission);
    assertThat(verdict.statusCode()).isEqualTo(200);
    JsonNode decided2 = mapper.readTree(verdict.body());
    assertThat(decided2.get("outcome").asString()).isEqualTo("ACCEPTED");

    HttpResponse<String> receipt = sessionGet("/api/bff/verification/decisions/"
        + decided2.get("decisionId").asString(), session, Map.of());
    assertThat(receipt.statusCode()).isEqualTo(200);
    assertThat(receipt.headers().firstValue("etag")).isPresent();
  }

  @Test
  void memberSessionCannotSubmitVerification() throws Exception {
    Prepared stage = prepare("bffm");
    BffTestSessions.Session session = login(List.of("sovra-members"));
    HttpResponse<String> review =
        sessionGet("/api/bff/consent/requests/" + stage.requestId(), session, Map.of());
    assertThat(review.statusCode()).isEqualTo(200);

    Map<String, Object> submission = VerificationFixtures.verifyBody(stage.holder(),
        stage.requestId(), VerificationFixtures.nonce(), ConsentFixtures.AUDIENCE, mapper);
    HttpResponse<String> verdict =
        postJson("/api/bff/verification/presentations", session, submission);
    assertThat(verdict.statusCode()).isEqualTo(403);
  }

  @Test
  void machineTokenRejectedOnHolderSurface() throws Exception {
    Prepared stage = prepare("bffx");
    HttpResponse<String> rejected = BffTestSessions.get(http,
        BASE + "/api/bff/consent/requests/" + stage.requestId(),
        Map.of("Authorization", "Bearer " + stage.rp().token()));
    assertThat(rejected.statusCode()).isEqualTo(401);
  }

  @Test
  void crossTenantRequestInvisibleToSession() throws Exception {
    TestAccount foreignIssuer =
        TestAccounts.create(owner, "bfff-issuer", Set.of("ISSUER_OPS"));
    TestAccount foreignRp = TestAccounts.createInTenant(
        owner, foreignIssuer.tenantId(), "bfff-rp", Set.of("RP_CLIENT"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String credentialId = ConsentFixtures.issueCredential(client, foreignIssuer, holder, mapper);
    Map<String, Object> created = ConsentFixtures.create(
        client, foreignRp, ConsentFixtures.createBody(UUID.fromString(credentialId)));
    BffTestSessions.Session session = login(List.of("sovra-members", "sovra-rp"));
    HttpResponse<String> missing = sessionGet(
        "/api/bff/consent/requests/" + created.get("requestId"), session, Map.of());
    assertThat(missing.statusCode()).isEqualTo(404);
    assertThat(missing.body()).isBlank();
  }
}
