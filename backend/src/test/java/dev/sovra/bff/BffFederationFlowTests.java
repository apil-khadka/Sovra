package dev.sovra.bff;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
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
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Federation and security-operations desk (SOV-026): trust-admin
 * humans review the proposal queue, onboard issuers through
 * maker/checker approval, read sanitized audit evidence and
 * alerts — and members cannot reach any of it.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
    properties = {
      "server.port=18085",
      "sovra.bff.enabled=true",
      "sovra.bff.require-https-issuer=false",
      "sovra.bff.redirect-uri=http://localhost:18085/login/oauth2/code/sovra",
      "sovra.bff.post-logout-redirect-uri=http://localhost:18085/",
      "spring.security.oauth2.client.registration.sovra.client-id=sovra-bff",
      "spring.security.oauth2.client.registration.sovra.client-secret=stub-secret",
      "spring.security.oauth2.client.registration.sovra.scope=openid,profile,groups,tenant",
      "spring.security.oauth2.client.registration.sovra.redirect-uri=http://localhost:18085/login/oauth2/code/sovra"
    })
class BffFederationFlowTests extends SovraAppRoleBase {

  static final String BASE = "http://localhost:18085";
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

  @Test
  void trustAdminsOnboardThroughMakerChecker() throws Exception {
    BffTestSessions.Session maker = login(
        List.of("sovra-members", "sovra-trust-admins"), List.of("webauthn"));
    BffTestSessions.Session checker = login(
        List.of("sovra-members", "sovra-trust-admins"), List.of("webauthn"));

    HttpResponse<String> snapshot =
        sessionGet("/api/bff/trust/snapshots/current", maker, Map.of());
    assertThat(snapshot.statusCode()).isEqualTo(200);
    assertThat(snapshot.body()).contains("synth-1");

    String keyId = "fed-" + UUID.randomUUID().toString().substring(0, 8);
    HttpResponse<String> proposed = postJson(
        "/api/bff/trust/proposals", maker,
        Map.of("issuers", List.of(issuer(keyId)), "policies", List.of(),
            "note", "federation onboarding test"));
    assertThat(proposed.statusCode()).isEqualTo(201);
    String proposalId = mapper.readTree(proposed.body()).get("proposalId").asString();
    String version = mapper.readTree(proposed.body()).get("version").asString();

    HttpResponse<String> queue = sessionGet("/api/bff/trust/proposals", checker, Map.of());
    assertThat(queue.statusCode()).isEqualTo(200);
    assertThat(queue.body()).contains(proposalId);
    assertThat(queue.body()).contains("PENDING");

    // Maker cannot approve their own onboarding (two-person rule).
    HttpResponse<String> selfApproved =
        postJson("/api/bff/trust/proposals/" + proposalId + "/approve", maker, Map.of());
    assertThat(selfApproved.statusCode()).isEqualTo(403);

    HttpResponse<String> approved =
        postJson("/api/bff/trust/proposals/" + proposalId + "/approve", checker, Map.of());
    assertThat(approved.statusCode()).isEqualTo(200);
    HttpResponse<String> activated =
        postJson("/api/bff/trust/snapshots/" + version + "/activate", checker, Map.of());
    assertThat(activated.statusCode()).isEqualTo(200);

    HttpResponse<String> reread = sessionGet("/api/bff/trust/proposals", checker, Map.of());
    assertThat(reread.body()).contains("ACTIVATED");
    HttpResponse<String> current =
        sessionGet("/api/bff/trust/snapshots/current", maker, Map.of());
    assertThat(current.body()).contains(keyId);
  }

  @Test
  void trustAdminsReadAuditAndAlerts() throws Exception {
    BffTestSessions.Session admin = login(
        List.of("sovra-members", "sovra-trust-admins"), List.of("webauthn"));
    HttpResponse<String> audit = sessionGet("/api/bff/audit/events?limit=5", admin, Map.of());
    assertThat(audit.statusCode()).isEqualTo(200);
    HttpResponse<String> alerts = sessionGet("/api/bff/alerts", admin, Map.of());
    assertThat(alerts.statusCode()).isEqualTo(200);
  }

  @Test
  void membersCannotReachFederationOrEvidence() throws Exception {
    BffTestSessions.Session member = login(List.of("sovra-members"), List.of("pwd"));
    assertThat(sessionGet("/api/bff/trust/proposals", member, Map.of()).statusCode())
        .isEqualTo(403);
    assertThat(postJson("/api/bff/trust/proposals", member, Map.of()).statusCode())
        .isEqualTo(403);
    assertThat(sessionGet("/api/bff/audit/events", member, Map.of()).statusCode())
        .isEqualTo(403);
    assertThat(sessionGet("/api/bff/alerts", member, Map.of()).statusCode()).isEqualTo(403);
  }

  @Test
  void machineProposalQueueNeedsTrustAdmin() {
    TestAccount ops = TestAccounts.create(owner, "fed-ops", Set.of("ISSUER_OPS"));
    TestAccount admin = TestAccounts.create(owner, "fed-admin", Set.of("TRUST_ADMIN"));
    assertThat(org.assertj.core.api.Assertions.catchException(() -> client.get()
        .uri("/api/trust/proposals").headers(ops.headers())
        .retrieve().body(String.class)))
        .isInstanceOf(
            org.springframework.web.client.HttpClientErrorException.Forbidden.class);
    String queue = client.get().uri("/api/trust/proposals").headers(admin.headers())
        .retrieve().body(String.class);
    assertThat(queue).contains("proposalId");
  }

  private BffTestSessions.Session login(List<String> groups, List<String> amr) throws Exception {
    String subject = "fed-" + UUID.randomUUID().toString().substring(0, 8);
    return BffTestSessions.login(
        http, mapper, BASE, STUB,
        new StubOpenIdProvider.Script(subject, groups, "sovra-demo", amr));
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

  private HttpResponse<String> sessionGet(
      String path, BffTestSessions.Session session, Map<String, String> extra) throws Exception {
    Map<String, String> headers = new java.util.HashMap<>(extra);
    headers.put("Cookie", "JSESSIONID=" + session.jsessionid());
    return BffTestSessions.get(http, BASE + path, headers);
  }

  static Map<String, Object> issuer(String keyId) {
    return Map.of(
        "issuerId", "fed-onboard-issuer",
        "displayName", "Federation onboard issuer",
        "scope", "adult-status",
        "credentialTypes", List.of("https://sovra.example/vct/adult-status/1"),
        "keyId", keyId,
        "publicKeyJwk", Map.of(
            "kty", "EC", "crv", "P-256", "kid", keyId,
            "x", "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y", "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"),
        "validFrom", Instant.now().minusSeconds(60).toString(),
        "validThrough", Instant.now().plusSeconds(3600).toString(),
        "status", "ACTIVE");
  }
}
