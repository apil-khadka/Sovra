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
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
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
import tools.jackson.databind.ObjectMapper;

/**
 * Issuer information-management desk (SOV-023): human operators
 * review extraction and enrollment queues, correct and approve
 * revisions, decide cases through maker/checker, view originals
 * under purpose-bound grants, and read their scoped audit trail —
 * while members and other tenants stay out.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
    properties = {
      "server.port=18086",
      "sovra.bff.enabled=true",
      "sovra.bff.require-https-issuer=false",
      "sovra.bff.redirect-uri=http://localhost:18086/login/oauth2/code/sovra",
      "sovra.bff.post-logout-redirect-uri=http://localhost:18086/",
      "spring.security.oauth2.client.registration.sovra.client-id=sovra-bff",
      "spring.security.oauth2.client.registration.sovra.client-secret=stub-secret",
      "spring.security.oauth2.client.registration.sovra.scope=openid,profile,groups,tenant",
      "spring.security.oauth2.client.registration.sovra.redirect-uri=http://localhost:18086/login/oauth2/code/sovra"
    })
// Frees this fixed-port context (and its JDBC pool) after the class: with six such
// contexts the shared test Postgres runs out of connection slots otherwise.
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class BffIssuerFlowTests extends SovraAppRoleBase {

  static final String BASE = "http://localhost:18086";

  static final String FIXTURE =
      "SOVRA-FIXTURE/v1\n"
          + "name: Ana Example\n"
          + "document_number: X1234567\n"
          + "date_of_birth: 1990-01-02\n"
          + "country: NL\n";

  /** Smallest valid 1x1 PNG, recognized by magic bytes. */
  static final byte[] PNG =
      Base64.getDecoder().decode(
          "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==");

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
  UUID demoTenant;

  @BeforeEach
  void setup() throws Exception {
    client = RestClient.builder().baseUrl(BASE).build();
    owner = new JdbcTemplate(ownerDataSource());
    owner.update(
        "INSERT INTO tenant (slug, display_name) VALUES ('sovra-demo', 'BFF demo')"
            + " ON CONFLICT (slug) DO NOTHING");
    demoTenant =
        owner.queryForObject(
            "SELECT id FROM tenant WHERE slug = 'sovra-demo'", UUID.class);
    IssuanceFixtures.ensureSyntheticIssuer(owner, trust, mapper);
    http = HttpClient.newBuilder().followRedirects(Redirect.NEVER).build();
  }

  @Test
  void humansReviewCasesThroughMakerChecker() throws Exception {
    TestAccount ops = TestAccounts.createInTenant(
        owner, demoTenant, "desk-ops-" + suffix(), Set.of("ISSUER_OPS"));
    ApprovedSource source = approvedSource(ops, FIXTURE);
    BffTestSessions.Session maker = login(List.of("sovra-ops"));
    BffTestSessions.Session checker = login(List.of("sovra-ops"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);

    HttpResponse<String> created = postJson(
        "/api/bff/issuer/enrollments", maker,
        Map.of(
            "vaultObjectId", source.objectId(),
            "extractionRecordId", source.recordId(),
            "holderJwk", mapper.convertValue(holder.jwk(), Map.class)));
    assertThat(created.statusCode()).isEqualTo(201);
    String enrollmentId = mapper.readTree(created.body()).get("enrollmentId").asString();

    HttpResponse<String> queue =
        sessionGet("/api/bff/issuer/enrollments?state=pending", checker, Map.of());
    assertThat(queue.statusCode()).isEqualTo(200);
    assertThat(queue.body()).contains(enrollmentId);

    assertThat(postJson(
        "/api/bff/issuer/enrollments/" + enrollmentId + "/submit", maker, Map.of())
        .statusCode()).isEqualTo(200);

    // The maker cannot approve their own case, even with a valid
    // holder binding proof.
    HttpResponse<String> selfApproved = postJson(
        "/api/bff/issuer/enrollments/" + enrollmentId + "/decision", maker,
        Map.of("revision", 1, "decision", "approve",
            "bindingProof", bindingProof(holder, enrollmentId, 1)));
    assertThat(selfApproved.statusCode()).isEqualTo(409);

    HttpResponse<String> decided = postJson(
        "/api/bff/issuer/enrollments/" + enrollmentId + "/decision", checker,
        Map.of("revision", 1, "decision", "approve",
            "bindingProof", bindingProof(holder, enrollmentId, 1)));
    assertThat(decided.statusCode()).isEqualTo(200);
    assertThat(decided.body()).contains("APPROVED");

    HttpResponse<String> reread =
        sessionGet("/api/bff/issuer/enrollments/" + enrollmentId, maker, Map.of());
    assertThat(reread.body()).contains("CURRENT");
  }

  @Test
  void humansCorrectApproveAndRevalidateExtraction() throws Exception {
    TestAccount ops = TestAccounts.createInTenant(
        owner, demoTenant, "desk-ext-" + suffix(), Set.of("ISSUER_OPS"));
    String recordId = runId(ops, storeFixture(ops, FIXTURE, List.of("extraction-run")));
    BffTestSessions.Session reviewer = login(List.of("sovra-ops"));

    HttpResponse<String> queue =
        sessionGet("/api/bff/issuer/extraction/records?state=pending", reviewer, Map.of());
    assertThat(queue.statusCode()).isEqualTo(200);
    assertThat(queue.body()).contains(recordId);

    HttpResponse<String> first =
        sessionGet("/api/bff/issuer/extraction/records/" + recordId, reviewer, Map.of());
    assertThat(first.statusCode()).isEqualTo(200);
    String etag = first.headers().firstValue("ETag").orElseThrow();
    assertThat(sessionGet("/api/bff/issuer/extraction/records/" + recordId, reviewer,
        Map.of("If-None-Match", etag)).statusCode()).isEqualTo(304);

    HttpResponse<String> corrected = postJson(
        "/api/bff/issuer/extraction/records/" + recordId + "/revisions", reviewer,
        Map.of(
            "fields", Map.of("name", "Ana Fixed", "document_number", "X1234567",
                "date_of_birth", "1990-01-02"),
            "confidence", 0.9));
    assertThat(corrected.statusCode()).isEqualTo(201);

    // The correction moved the head: the old tag no longer matches.
    assertThat(sessionGet("/api/bff/issuer/extraction/records/" + recordId, reviewer,
        Map.of("If-None-Match", etag)).statusCode()).isEqualTo(200);

    HttpResponse<String> approved = postJson(
        "/api/bff/issuer/extraction/records/" + recordId + "/approval", reviewer,
        Map.of("revision", 2));
    assertThat(approved.statusCode()).isEqualTo(200);
    assertThat(approved.body()).contains("\"approvedRevision\":2");
  }

  @Test
  void reviewViewServesOnlyRealImages() throws Exception {
    TestAccount ops = TestAccounts.createInTenant(
        owner, demoTenant, "desk-img-" + suffix(), Set.of("ISSUER_OPS"));
    String pngObject = storeBytes(ops, PNG, List.of("issuer-review"));
    String textObject = storeBytes(
        ops, FIXTURE.getBytes(StandardCharsets.UTF_8), List.of("issuer-review"));
    String unscopedObject = storeBytes(ops, PNG, List.of("extraction-run"));
    BffTestSessions.Session reviewer = login(List.of("sovra-ops"));

    HttpResponse<String> view = postJson("/api/bff/issuer/vault/review-view", reviewer,
        Map.of("objectId", pngObject, "version", 1));
    assertThat(view.statusCode()).isEqualTo(200);
    assertThat(mapper.readTree(view.body()).get("contentType").asString())
        .isEqualTo("image/png");
    assertThat(Base64.getDecoder().decode(
        mapper.readTree(view.body()).get("contentBase64").asString())).isEqualTo(PNG);

    // Stored bytes that are not an image fail closed, and the
    // single-use grant dies with the attempt.
    HttpResponse<String> refused = postJson("/api/bff/issuer/vault/review-view", reviewer,
        Map.of("objectId", textObject, "version", 1));
    assertThat(refused.statusCode()).isEqualTo(400);
    Integer liveGrants = owner.queryForObject(
        "SELECT COUNT(*) FROM vault_grant WHERE object_id = ? AND revoked = FALSE",
        Integer.class, UUID.fromString(textObject));
    assertThat(liveGrants).isEqualTo(0);

    // Versions that never authorized the review purpose stay out.
    HttpResponse<String> unscoped = postJson("/api/bff/issuer/vault/review-view", reviewer,
        Map.of("objectId", unscopedObject, "version", 1));
    assertThat(unscoped.statusCode()).isEqualTo(400);
  }

  @Test
  void scopedAuditShowsCaseworkOnly() throws Exception {
    TestAccount ops = TestAccounts.createInTenant(
        owner, demoTenant, "desk-audit-" + suffix(), Set.of("ISSUER_OPS"));
    String recordId = runId(ops, storeFixture(ops, FIXTURE, List.of("extraction-run")));
    BffTestSessions.Session reviewer = login(List.of("sovra-ops"));
    assertThat(postJson(
        "/api/bff/issuer/extraction/records/" + recordId + "/approval", reviewer,
        Map.of("revision", 1)).statusCode()).isEqualTo(200);

    HttpResponse<String> audit =
        sessionGet("/api/bff/issuer/audit/events?limit=50", reviewer, Map.of());
    assertThat(audit.statusCode()).isEqualTo(200);
    assertThat(audit.body()).contains("EXTRACTION_APPROVE");
    assertThat(audit.body()).doesNotContain("BFF_LOGIN");
    assertThat(audit.body())
        .doesNotContain("PROPOSE_TRUST_CHANGE")
        .doesNotContain("CREATE_SERVICE_ACCOUNT");
  }

  @Test
  void membersAndStrangersCannotReachIssuerDesk() throws Exception {
    BffTestSessions.Session member = login(List.of("sovra-members"));
    assertThat(sessionGet("/api/bff/issuer/extraction/records", member, Map.of())
        .statusCode()).isEqualTo(403);
    assertThat(sessionGet("/api/bff/issuer/enrollments", member, Map.of()).statusCode())
        .isEqualTo(403);
    assertThat(postJson("/api/bff/issuer/vault/review-view", member,
        Map.of("objectId", UUID.randomUUID().toString(), "version", 1)).statusCode())
        .isEqualTo(403);
    assertThat(sessionGet("/api/bff/issuer/audit/events", member, Map.of()).statusCode())
        .isEqualTo(403);

    // Other tenants' cases never resolve, even by id.
    BffTestSessions.Session reviewer = login(List.of("sovra-ops"));
    assertThat(sessionGet(
        "/api/bff/issuer/extraction/records/" + UUID.randomUUID(), reviewer, Map.of())
        .statusCode()).isEqualTo(404);
    HttpResponse<String> anonymous =
        http.send(HttpRequest.newBuilder(URI.create(BASE + "/api/bff/issuer/enrollments"))
            .timeout(Duration.ofSeconds(30)).GET().build(),
            HttpResponse.BodyHandlers.ofString());
    assertThat(anonymous.statusCode()).isEqualTo(401);
  }

  @Test
  void membersOnboardSandboxThroughPortalSessions() throws Exception {
    BffTestSessions.Session member = login(List.of("sovra-members"));
    HttpResponse<String> created = postJson(
        "/api/bff/portal/sandbox/accounts", member, Map.of("name", "sandbox-desk-" + suffix()));
    assertThat(created.statusCode()).isEqualTo(201);
    assertThat(created.body()).contains("RP_CLIENT").contains("token");

    HttpResponse<String> listed =
        sessionGet("/api/bff/portal/sandbox/accounts", member, Map.of());
    assertThat(listed.statusCode()).isEqualTo(200);
    assertThat(listed.body()).contains("sandbox-desk-").doesNotContain("token");

    HttpResponse<String> metrics = sessionGet("/api/bff/portal/rp/metrics", member, Map.of());
    assertThat(metrics.statusCode()).isEqualTo(200);
    assertThat(metrics.body()).contains("total");
  }

  @Test
  void portalSessionsKeepIssuerAndStrangersOut() throws Exception {
    TestAccount admin = TestAccounts.createInTenant(
        owner, demoTenant, "portal-hidden-" + suffix(), Set.of("TRUST_ADMIN"));
    BffTestSessions.Session reviewer = login(List.of("sovra-ops"));
    assertThat(postJson("/api/bff/portal/sandbox/accounts", reviewer,
        Map.of("name", "sandbox-nope")).statusCode()).isEqualTo(403);

    // Members manage RP credentials only: the trust admin 404s like unknown.
    BffTestSessions.Session member = login(List.of("sovra-members"));
    assertThat(postJson(
        "/api/bff/portal/rp/credentials/" + admin.accountId() + "/rotate", member, Map.of())
        .statusCode()).isEqualTo(404);

    HttpResponse<String> anonymous =
        http.send(HttpRequest.newBuilder(URI.create(BASE + "/api/bff/portal/rp/apps"))
            .timeout(Duration.ofSeconds(30)).GET().build(),
            HttpResponse.BodyHandlers.ofString());
    assertThat(anonymous.statusCode()).isEqualTo(401);
  }

  private String suffix() {
    return UUID.randomUUID().toString().substring(0, 8);
  }

  private BffTestSessions.Session login(List<String> groups) throws Exception {
    String subject = "desk-" + UUID.randomUUID().toString().substring(0, 8);
    return BffTestSessions.login(
        http, mapper, BASE, STUB,
        new StubOpenIdProvider.Script(subject, groups, "sovra-demo", List.of("pwd")));
  }

  private String bindingProof(
      IssuanceFixtures.HolderKeys holder, String enrollmentId, int revision) throws Exception {
    return IssuanceFixtures.proofOver(
        holder, "enrollment-binding\n" + enrollmentId + "\n" + revision, mapper);
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

  private record FixtureSource(String objectId, String grantId) {}

  private record ApprovedSource(String objectId, String recordId) {}

  private FixtureSource storeFixture(
      TestAccount issuer, String text, List<String> purposes) {
    List<String> stored = purposes.contains("extraction-run")
        ? purposes
        : java.util.stream.Stream.concat(purposes.stream(), java.util.stream.Stream.of(
            "extraction-run")).toList();
    String objectId = storeBytes(issuer, text.getBytes(StandardCharsets.UTF_8), stored);
    Map<String, Object> granted = machinePost("/api/vault/grants", issuer, Map.of(
        "objectId", objectId,
        "objectVersion", 1,
        "principalType", "service_account",
        "principalId", issuer.accountId().toString(),
        "purpose", "extraction-run",
        "workload", "sovra-test",
        "ttlSeconds", 3600));
    return new FixtureSource(objectId, granted.get("grantId").toString());
  }

  private String storeBytes(TestAccount issuer, byte[] content, List<String> purposes) {
    Map<String, Object> stored = machinePost("/api/vault/objects", issuer, Map.of(
        "issuerId", "https://issuer.example/desk-1",
        "displayName", "desk source",
        "purposes", purposes,
        "contentBase64", Base64.getEncoder().encodeToString(content),
        "contentSha256Hex", sha256Hex(content)));
    return stored.get("objectId").toString();
  }

  private String runId(TestAccount issuer, FixtureSource source) {
    Map<String, Object> run = machinePost("/api/extraction/records", issuer, Map.of(
        "vaultObjectId", source.objectId(),
        "objectVersion", 1,
        "grantId", source.grantId(),
        "purpose", "extraction-run",
        "workload", "sovra-test",
        "schemaId", "fixture-doc-v1"));
    return run.get("recordId").toString();
  }

  private ApprovedSource approvedSource(TestAccount maker, String text) {
    FixtureSource source = storeFixture(maker, text, List.of("extraction-run"));
    String recordId = runId(maker, source);
    machinePost("/api/extraction/records/" + recordId + "/approval", maker,
        Map.of("revision", 1));
    return new ApprovedSource(source.objectId(), recordId);
  }

  private static String sha256Hex(byte[] content) {
    try {
      return HexFormat.of().formatHex(
          java.security.MessageDigest.getInstance("SHA-256").digest(content));
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private Map<String, Object> machinePost(
      String uri, TestAccount account, Map<String, Object> body) {
    return client.post().uri(uri).headers(account.headers()).body(body)
        .retrieve().body(Map.class);
  }
}
