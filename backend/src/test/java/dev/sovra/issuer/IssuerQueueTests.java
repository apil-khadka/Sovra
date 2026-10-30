package dev.sovra.issuer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.issuance.IssuanceFixtures;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Issuer review queues (SOV-023): extraction and enrollment
 * listings with posture filters, keyset cursors, tenant
 * isolation, and summaries that carry no field values.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class IssuerQueueTests extends SovraAppRoleBase {

  static final String FIXTURE =
      "SOVRA-FIXTURE/v1\n"
          + "name: Ana Example\n"
          + "document_number: X1234567\n"
          + "date_of_birth: 1990-01-02\n"
          + "country: NL\n";

  @LocalServerPort int port;

  @Autowired javax.sql.DataSource dataSource;

  @Autowired ObjectMapper mapper;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
  }

  @Test
  @SuppressWarnings("unchecked")
  void extractionQueueFiltersAndPages() {
    TestAccount issuer = TestAccounts.create(owner, "queue-ext", Set.of("ISSUER_OPS"));
    String pending = runId(issuer, storeFixture(issuer, FIXTURE));
    String approved = runId(issuer, storeFixture(issuer, FIXTURE));
    post("/api/extraction/records/" + approved + "/approval", issuer.headers(),
        Map.of("revision", 1));

    Map<String, Object> all = get("/api/extraction/records", issuer.headers());
    assertThat(ids(all)).contains(pending, approved);
    Map<String, Object> first = item(all, pending);
    assertThat(first.get("engineId")).isEqualTo("fixture-v1");
    assertThat(first.get("approvedRevision")).isNull();
    assertThat(first.get("latestRevision")).isEqualTo(1);
    // Summaries carry queue metadata only — no field values, no digests.
    assertThat(first).doesNotContainKeys("observed", "normalized", "canonicalDigests",
        "exactDigests", "revisions", "sourceDigestHex");

    assertThat(ids(get("/api/extraction/records?state=pending", issuer.headers())))
        .contains(pending)
        .doesNotContain(approved);
    assertThat(ids(get("/api/extraction/records?state=approved", issuer.headers())))
        .contains(approved)
        .doesNotContain(pending);
    assertThat(ids(get("/api/extraction/records?state=stale", issuer.headers()))).isEmpty();

    // Correction below a new head marks the approval stale.
    post("/api/extraction/records/" + approved + "/revisions", issuer.headers(), Map.of(
        "fields", Map.of("name", "Ana Fixed", "document_number", "X1234567",
            "date_of_birth", "1990-01-02"),
        "confidence", 0.9));
    assertThat(ids(get("/api/extraction/records?state=stale", issuer.headers())))
        .contains(approved);

    Map<String, Object> page1 = get("/api/extraction/records?limit=1", issuer.headers());
    assertThat(((List<?>) page1.get("items"))).hasSize(1);
    assertThat(page1.get("nextCursor")).isNotNull();
    Map<String, Object> page2 = get(
        "/api/extraction/records?limit=1&cursor=" + page1.get("nextCursor"), issuer.headers());
    assertThat(((List<?>) page2.get("items"))).hasSize(1);
    assertThat(itemId(page2, 0)).isNotEqualTo(itemId(page1, 0));
    assertThat(page2.get("nextCursor")).isNull();

    assertThatThrownBy(() -> get("/api/extraction/records?state=bogus", issuer.headers()))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    assertThatThrownBy(() -> get("/api/extraction/records?cursor=!!!", issuer.headers()))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  @SuppressWarnings("unchecked")
  void enrollmentQueueFiltersAndPages() throws Exception {
    TestAccount maker = TestAccounts.create(owner, "queue-enr", Set.of("ISSUER_OPS"));
    TestAccount checker = TestAccounts.createInTenant(
        owner, maker.tenantId(), "queue-enr-checker", Set.of("ISSUER_OPS"));
    ApprovedSource source = approvedSource(maker, FIXTURE);
    String fresh = enroll(maker, source, IssuanceFixtures.generateHolder(mapper));
    String decided = enroll(maker, source, IssuanceFixtures.generateHolder(mapper));
    post("/api/enrollments/" + decided + "/submit", maker.headers(), Map.of());
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String approved = enroll(maker, source, holder);
    post("/api/enrollments/" + approved + "/submit", maker.headers(), Map.of());
    post("/api/enrollments/" + approved + "/decision", checker.headers(), Map.of(
        "revision", 1, "decision", "approve",
        "bindingProof", IssuanceFixtures.proofOver(
            holder, "enrollment-binding\n" + approved + "\n1", mapper)));

    Map<String, Object> all = get("/api/enrollments", maker.headers());
    assertThat(enrollmentIds(all)).contains(fresh, decided, approved);
    Map<String, Object> approvedRow = enrollmentItem(all, approved);
    assertThat(approvedRow.get("state")).isEqualTo("APPROVED");
    assertThat(approvedRow.get("eligible")).isEqualTo(Boolean.TRUE);
    assertThat(approvedRow.get("eligibilityReason")).isEqualTo("CURRENT");
    assertThat(approvedRow).doesNotContainKeys("claims", "holderJwk", "reviews");

    assertThat(enrollmentIds(get("/api/enrollments?state=pending", maker.headers())))
        .containsExactly(fresh);
    assertThat(enrollmentIds(get("/api/enrollments?state=in_review", maker.headers())))
        .containsExactly(decided);
    assertThat(enrollmentIds(get("/api/enrollments?state=approved", maker.headers())))
        .containsExactly(approved);
    assertThat(enrollmentIds(get("/api/enrollments?state=rejected", maker.headers()))).isEmpty();

    Map<String, Object> page1 = get("/api/enrollments?limit=2", maker.headers());
    assertThat(((List<?>) page1.get("items"))).hasSize(2);
    assertThat(page1.get("nextCursor")).isNotNull();
    Map<String, Object> page2 = get(
        "/api/enrollments?limit=2&cursor=" + page1.get("nextCursor"), maker.headers());
    assertThat(((List<?>) page2.get("items"))).hasSize(1);
    assertThat(page2.get("nextCursor")).isNull();

    assertThatThrownBy(() -> get("/api/enrollments?state=bogus", maker.headers()))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void queuesRefuseMembersAndIsolateTenants() {
    TestAccount issuer = TestAccounts.create(owner, "queue-iso", Set.of("ISSUER_OPS"));
    TestAccount member = TestAccounts.createInTenant(
        owner, issuer.tenantId(), "queue-member", Set.of("TENANT_MEMBER"));
    TestAccount stranger = TestAccounts.create(owner, "queue-stranger", Set.of("ISSUER_OPS"));
    runId(issuer, storeFixture(issuer, FIXTURE));

    assertThatThrownBy(() -> get("/api/extraction/records", member.headers()))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(() -> get("/api/enrollments", member.headers()))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    Map<String, Object> foreign = get("/api/extraction/records", stranger.headers());
    assertThat(((List<?>) foreign.get("items"))).isEmpty();
  }

  @SuppressWarnings("unchecked")
  private List<String> ids(Map<String, Object> page) {
    return ((List<Map<String, Object>>) page.get("items"))
        .stream().map(item -> item.get("recordId").toString()).toList();
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> item(Map<String, Object> page, String recordId) {
    return ((List<Map<String, Object>>) page.get("items"))
        .stream().filter(item -> item.get("recordId").toString().equals(recordId))
        .findFirst().orElseThrow();
  }

  @SuppressWarnings("unchecked")
  private String itemId(Map<String, Object> page, int index) {
    return ((List<Map<String, Object>>) page.get("items")).get(index).get("recordId").toString();
  }

  @SuppressWarnings("unchecked")
  private List<String> enrollmentIds(Map<String, Object> page) {
    return ((List<Map<String, Object>>) page.get("items"))
        .stream().map(item -> item.get("enrollmentId").toString()).toList();
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> enrollmentItem(Map<String, Object> page, String enrollmentId) {
    return ((List<Map<String, Object>>) page.get("items"))
        .stream().filter(item -> item.get("enrollmentId").toString().equals(enrollmentId))
        .findFirst().orElseThrow();
  }

  private record FixtureSource(String objectId, String grantId) {}

  private record ApprovedSource(String objectId, String recordId) {}

  private FixtureSource storeFixture(TestAccount issuer, String text) {
    byte[] content = text.getBytes(StandardCharsets.UTF_8);
    Map<String, Object> stored = post("/api/vault/objects", issuer.headers(), Map.of(
        "issuerId", "https://issuer.example/queue-1",
        "displayName", "queue source",
        "purposes", List.of("extraction-run"),
        "contentBase64", Base64.getEncoder().encodeToString(content),
        "contentSha256Hex", sha256Hex(text)));
    String objectId = stored.get("objectId").toString();
    Map<String, Object> granted = post("/api/vault/grants", issuer.headers(), Map.of(
        "objectId", objectId,
        "objectVersion", 1,
        "principalType", "service_account",
        "principalId", issuer.accountId().toString(),
        "purpose", "extraction-run",
        "workload", "sovra-test",
        "ttlSeconds", 3600));
    return new FixtureSource(objectId, granted.get("grantId").toString());
  }

  private String runId(TestAccount issuer, FixtureSource source) {
    Map<String, Object> run = post("/api/extraction/records", issuer.headers(), Map.of(
        "vaultObjectId", source.objectId(),
        "objectVersion", 1,
        "grantId", source.grantId(),
        "purpose", "extraction-run",
        "workload", "sovra-test",
        "schemaId", "fixture-doc-v1"));
    return run.get("recordId").toString();
  }

  private ApprovedSource approvedSource(TestAccount maker, String text) {
    FixtureSource source = storeFixture(maker, text);
    String recordId = runId(maker, source);
    post("/api/extraction/records/" + recordId + "/approval", maker.headers(),
        Map.of("revision", 1));
    return new ApprovedSource(source.objectId(), recordId);
  }

  private String enroll(
      TestAccount maker, ApprovedSource source, IssuanceFixtures.HolderKeys holder) {
    Map<String, Object> created = post("/api/enrollments", maker.headers(), Map.of(
        "vaultObjectId", source.objectId(),
        "extractionRecordId", source.recordId(),
        "holderJwk", mapper.convertValue(holder.jwk(), Map.class)));
    return created.get("enrollmentId").toString();
  }

  private static String sha256Hex(String text) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
          .digest(text.getBytes(StandardCharsets.UTF_8)));
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private Map<String, Object> get(String uri, Consumer<HttpHeaders> headers) {
    return client.get().uri(uri).headers(headers).retrieve().body(Map.class);
  }

  private Map<String, Object> post(
      String uri, Consumer<HttpHeaders> headers, Map<String, Object> body) {
    return client.post().uri(uri).headers(headers).body(body).retrieve().body(Map.class);
  }
}
