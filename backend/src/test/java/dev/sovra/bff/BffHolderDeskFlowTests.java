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
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
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
 * Holder dashboard (SOV-024): members unlock with a holder-key
 * proof and read exactly that key's cases, disclosures,
 * credentials, and recovery. Locked sessions, other holders'
 * rows, and non-member roles stay out.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
    properties = {
      "server.port=18087",
      "sovra.bff.enabled=true",
      "sovra.bff.require-https-issuer=false",
      "sovra.bff.redirect-uri=http://localhost:18087/login/oauth2/code/sovra",
      "sovra.bff.post-logout-redirect-uri=http://localhost:18087/",
      "spring.security.oauth2.client.registration.sovra.client-id=sovra-bff",
      "spring.security.oauth2.client.registration.sovra.client-secret=stub-secret",
      "spring.security.oauth2.client.registration.sovra.scope=openid,profile,groups,tenant",
      "spring.security.oauth2.client.registration.sovra.redirect-uri=http://localhost:18087/login/oauth2/code/sovra"
    })
// Frees this fixed-port context (and its JDBC pool) after the class: with six such
// contexts the shared test Postgres runs out of connection slots otherwise.
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class BffHolderDeskFlowTests extends SovraAppRoleBase {

  static final String BASE = "http://localhost:18087";

  static final String FIXTURE =
      "SOVRA-FIXTURE/v1\n"
          + "name: Ana Example\n"
          + "document_number: X1234567\n"
          + "date_of_birth: 1990-01-02\n"
          + "country: NL\n";

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
  void unlockedHolderReadsTheirWholeHistory() throws Exception {
    TestAccount ops = TestAccounts.createInTenant(
        owner, demoTenant, "holder-ops-" + suffix(), Set.of("ISSUER_OPS"));
    TestAccount rp = TestAccounts.createInTenant(
        owner, demoTenant, "holder-rp-" + suffix(), Set.of("RP_CLIENT", "TENANT_MEMBER"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String thumbprint = IssuanceFixtures.thumbprint(holder);

    // Full journey first: enrolled, approved, issued, disclosed, verified.
    ApprovedSource source = approvedSource(ops);
    String enrollmentId = enroll(ops, source, holder);
    machinePost("/api/enrollments/" + enrollmentId + "/submit", ops, Map.of());
    TestAccount checker = TestAccounts.createInTenant(
        owner, demoTenant, "holder-checker-" + suffix(), Set.of("ISSUER_OPS"));
    machinePost("/api/enrollments/" + enrollmentId + "/decision", checker, Map.of(
        "revision", 1, "decision", "approve",
        "bindingProof", IssuanceFixtures.proofOver(
            holder, "enrollment-binding\n" + enrollmentId + "\n1", mapper)));
    String credentialId = ConsentFixtures.issueCredential(client, ops, holder, mapper);
    Map<String, Object> created =
        ConsentFixtures.create(client, rp, ConsentFixtures.createBody(UUID.fromString(credentialId)));
    String requestId = created.get("requestId").toString();
    Map<String, Object> review = ConsentFixtures.review(client, rp, requestId);
    ConsentFixtures.decide(client, rp, requestId,
        ConsentFixtures.decideBody(holder, review, "approve", mapper));
    VerificationFixtures.verify(client, rp, VerificationFixtures.verifyBody(
        holder, requestId, VerificationFixtures.nonce(), ConsentFixtures.AUDIENCE, mapper));

    BffTestSessions.Session member = login(List.of("sovra-members"));
    // Locked first: every self-read refuses without the key proof.
    assertThat(sessionGet("/api/bff/holder/cases", member).statusCode()).isEqualTo(403);
    assertThat(sessionGet("/api/bff/holder/consents", member).statusCode()).isEqualTo(403);
    assertThat(sessionGet("/api/bff/holder/credentials", member).statusCode()).isEqualTo(403);
    assertThat(sessionGet("/api/bff/holder/recovery", member).statusCode()).isEqualTo(403);

    unlock(member, holder);

    HttpResponse<String> cases = sessionGet("/api/bff/holder/cases", member);
    assertThat(cases.statusCode()).isEqualTo(200);
    assertThat(cases.body()).contains(enrollmentId).contains("CURRENT");
    HttpResponse<String> detail =
        sessionGet("/api/bff/holder/cases/" + enrollmentId, member);
    assertThat(detail.statusCode()).isEqualTo(200);
    assertThat(detail.body()).contains("Ana Example").contains("observed");

    HttpResponse<String> consents = sessionGet("/api/bff/holder/consents", member);
    assertThat(consents.statusCode()).isEqualTo(200);
    assertThat(consents.body())
        .contains(requestId)
        .contains("synthetic age check at checkout")
        .contains("ACCEPTED");

    HttpResponse<String> credentials = sessionGet("/api/bff/holder/credentials", member);
    assertThat(credentials.statusCode()).isEqualTo(200);
    assertThat(credentials.body()).contains(credentialId).contains("VALID");

    HttpResponse<String> recovery = sessionGet("/api/bff/holder/recovery", member);
    assertThat(recovery.statusCode()).isEqualTo(200);
    assertThat(recovery.body()).contains(thumbprint).contains("ACTIVE");

    // A bad proof never unlocks, and locking re-arms the refusal.
    BffTestSessions.Session other = login(List.of("sovra-members"));
    HttpResponse<String> denied = postJson("/api/bff/holder/unlock", other, Map.of(
        "holderJwk", mapper.convertValue(holder.jwk(), Map.class), "proof", "bogus"));
    assertThat(denied.statusCode()).isEqualTo(400);
    assertThat(postJson("/api/bff/holder/lock", member, Map.of()).statusCode()).isEqualTo(200);
    assertThat(sessionGet("/api/bff/holder/cases", member).statusCode()).isEqualTo(403);
    assertThat(sessionGet("/api/bff/holder/cases/" + enrollmentId, other).statusCode())
        .isEqualTo(403);
  }

  @Test
  void holdersCannotReachEachOthersCases() throws Exception {
    TestAccount ops = TestAccounts.createInTenant(
        owner, demoTenant, "holder-x-" + suffix(), Set.of("ISSUER_OPS"));
    ApprovedSource source = approvedSource(ops);
    IssuanceFixtures.HolderKeys first = IssuanceFixtures.generateHolder(mapper);
    IssuanceFixtures.HolderKeys second = IssuanceFixtures.generateHolder(mapper);
    String firstCase = enroll(ops, source, first);
    enroll(ops, source, second);

    BffTestSessions.Session member = login(List.of("sovra-members"));
    unlock(member, first);
    HttpResponse<String> cases = sessionGet("/api/bff/holder/cases", member);
    assertThat(cases.statusCode()).isEqualTo(200);
    assertThat(cases.body()).contains(firstCase);
    // The second holder's case id guesses back 404, indistinguishable
    // from unknown — and the unlocked key's own case resolves.
    assertThat(sessionGet("/api/bff/holder/cases/" + firstCase, member).statusCode())
        .isEqualTo(200);
    String strangers = owner.queryForObject(
        "SELECT id::text FROM enrollment WHERE holder_thumbprint = ? ORDER BY created_at DESC"
            + " LIMIT 1",
        String.class, IssuanceFixtures.thumbprint(second));
    assertThat(sessionGet("/api/bff/holder/cases/" + strangers, member).statusCode())
        .isEqualTo(404);
  }

  @Test
  void recoveryStateFollowsLossReports() throws Exception {
    TestAccount ops = TestAccounts.createInTenant(
        owner, demoTenant, "holder-rec-" + suffix(), Set.of("ISSUER_OPS"));
    ApprovedSource source = approvedSource(ops);
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String enrollmentId = enroll(ops, source, holder);
    machinePost("/api/enrollments/" + enrollmentId + "/submit", ops, Map.of());
    TestAccount checker = TestAccounts.createInTenant(
        owner, demoTenant, "holder-rec-checker-" + suffix(), Set.of("ISSUER_OPS"));
    machinePost("/api/enrollments/" + enrollmentId + "/decision", checker, Map.of(
        "revision", 1, "decision", "approve",
        "bindingProof", IssuanceFixtures.proofOver(
            holder, "enrollment-binding\n" + enrollmentId + "\n1", mapper)));

    BffTestSessions.Session member = login(List.of("sovra-members"));
    unlock(member, holder);
    assertThat(sessionGet("/api/bff/holder/recovery", member).body()).contains("ACTIVE");

    machinePost("/api/holder-keys/report", ops, Map.of(
        "thumbprint", IssuanceFixtures.thumbprint(holder), "reason", "loss"));
    HttpResponse<String> after = sessionGet("/api/bff/holder/recovery", member);
    assertThat(after.statusCode()).isEqualTo(200);
    assertThat(after.body()).contains("COMPROMISED").contains("REPORTED");
  }

  @Test
  void operatorSessionsCannotUseHolderReads() throws Exception {
    BffTestSessions.Session ops = login(List.of("sovra-ops"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    // The key proof verifies, but the role gate still refuses: holder
    // self-reads belong to member sessions, operator reads to the desk.
    unlock(ops, holder);
    assertThat(sessionGet("/api/bff/holder/cases", ops).statusCode()).isEqualTo(403);
  }

  private String suffix() {
    return UUID.randomUUID().toString().substring(0, 8);
  }

  private BffTestSessions.Session login(List<String> groups) throws Exception {
    String subject = "holder-" + UUID.randomUUID().toString().substring(0, 8);
    return BffTestSessions.login(
        http, mapper, BASE, STUB,
        new StubOpenIdProvider.Script(subject, groups, "sovra-demo", List.of("pwd")));
  }

  private void unlock(BffTestSessions.Session session, IssuanceFixtures.HolderKeys holder)
      throws Exception {
    HttpResponse<String> challenge = sessionGet("/api/bff/holder/challenge", session);
    assertThat(challenge.statusCode()).isEqualTo(200);
    String value = mapper.readTree(challenge.body()).get("challenge").asString();
    String proof = IssuanceFixtures.proofOver(
        holder,
        "holder-unlock/v1\n" + value + "\n" + IssuanceFixtures.thumbprint(holder),
        mapper);
    HttpResponse<String> unlocked = postJson("/api/bff/holder/unlock", session, Map.of(
        "holderJwk", mapper.convertValue(holder.jwk(), Map.class), "proof", proof));
    assertThat(unlocked.statusCode()).isEqualTo(200);
    assertThat(unlocked.body()).contains(IssuanceFixtures.thumbprint(holder));
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

  private HttpResponse<String> sessionGet(String path, BffTestSessions.Session session)
      throws Exception {
    return BffTestSessions.get(
        http, BASE + path, Map.of("Cookie", "JSESSIONID=" + session.jsessionid()));
  }

  private record FixtureSource(String objectId, String grantId) {}

  private record ApprovedSource(String objectId, String recordId) {}

  private ApprovedSource approvedSource(TestAccount maker) {
    byte[] content = FIXTURE.getBytes(StandardCharsets.UTF_8);
    Map<String, Object> stored = machinePost("/api/vault/objects", maker, Map.of(
        "issuerId", "https://issuer.example/holder-1",
        "displayName", "holder source",
        "purposes", List.of("extraction-run"),
        "contentBase64", Base64.getEncoder().encodeToString(content),
        "contentSha256Hex", sha256Hex(content)));
    String objectId = stored.get("objectId").toString();
    Map<String, Object> granted = machinePost("/api/vault/grants", maker, Map.of(
        "objectId", objectId,
        "objectVersion", 1,
        "principalType", "service_account",
        "principalId", maker.accountId().toString(),
        "purpose", "extraction-run",
        "workload", "sovra-test",
        "ttlSeconds", 3600));
    Map<String, Object> run = machinePost("/api/extraction/records", maker, Map.of(
        "vaultObjectId", objectId,
        "objectVersion", 1,
        "grantId", granted.get("grantId").toString(),
        "purpose", "extraction-run",
        "workload", "sovra-test",
        "schemaId", "fixture-doc-v1"));
    String recordId = run.get("recordId").toString();
    machinePost(
        "/api/extraction/records/" + recordId + "/approval", maker, Map.of("revision", 1));
    return new ApprovedSource(objectId, recordId);
  }

  private String enroll(
      TestAccount maker, ApprovedSource source, IssuanceFixtures.HolderKeys holder) {
    Map<String, Object> created = machinePost("/api/enrollments", maker, Map.of(
        "vaultObjectId", source.objectId(),
        "extractionRecordId", source.recordId(),
        "holderJwk", mapper.convertValue(holder.jwk(), Map.class)));
    return created.get("enrollmentId").toString();
  }

  private static String sha256Hex(byte[] content) {
    try {
      return java.util.HexFormat.of().formatHex(
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
