package dev.sovra.extraction;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
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

/**
 * Extraction happy paths (SOV-018, AC-11/12): run from a vault
 * source, provenance-rich reads, corrections that append
 * revisions, approval pinning, and stale-approval conflicts.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ExtractionFlowTests extends SovraAppRoleBase {

  static final String FIXTURE =
      "SOVRA-FIXTURE/v1\n"
          + "name: Ana Example\n"
          + "document_number: X1234567\n"
          + "date_of_birth: 1990-01-02\n"
          + "country: NL\n";

  @LocalServerPort int port;

  @Autowired javax.sql.DataSource dataSource;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
  }

  @Test
  @SuppressWarnings("unchecked")
  void runCorrectApproveRoundTrip() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "ext-issuer", Set.of("ISSUER_OPS"));
    FixtureSource source = storeFixture(issuer, FIXTURE);

    Map<String, Object> run = post("/api/extraction/records", issuer.headers(), Map.of(
        "vaultObjectId", source.objectId(),
        "objectVersion", 1,
        "grantId", source.grantId(),
        "purpose", "extraction-run",
        "workload", "sovra-test",
        "schemaId", "fixture-doc-v1"));
    String recordId = run.get("recordId").toString();
    assertThat(run.get("revision")).isEqualTo(1);
    String sourceDigest = HexFormat.of().formatHex(
        MessageDigest.getInstance("SHA-256").digest(FIXTURE.getBytes(StandardCharsets.UTF_8)));
    assertThat(run.get("sourceDigestHex")).isEqualTo(sourceDigest);

    Map<String, Object> read = get("/api/extraction/records/" + recordId, issuer.headers());
    assertThat(read.get("engineId")).isEqualTo("fixture-v1");
    assertThat(read.get("schemaId")).isEqualTo("fixture-doc-v1");
    assertThat(read.get("normalizerId")).isEqualTo("normalizer-v1");
    assertThat(read.get("canonId")).isEqualTo("canon-v1");
    assertThat(read.get("approvedRevision")).isNull();
    List<Map<String, Object>> revisions = (List<Map<String, Object>>) read.get("revisions");
    assertThat(revisions).hasSize(1);
    Map<String, Object> rev = revisions.get(0);
    assertThat(rev.get("revNo")).isEqualTo(1);
    assertThat(rev.get("supersedes")).isNull();
    Map<String, String> observed = (Map<String, String>) rev.get("observed");
    assertThat(observed.get("name")).isEqualTo("Ana Example");
    Map<String, String> normalized = (Map<String, String>) rev.get("normalized");
    assertThat(normalized.get("name")).isEqualTo("ana example");
    assertThat(normalized.get("document_number")).isEqualTo("X1234567");
    // Digests recomputed independently in the test, not by the
    // production digest helper.
    Map<String, String> canonical = (Map<String, String>) rev.get("canonicalDigests");
    assertThat(canonical.get("name")).isEqualTo(sha256Hex("ana example"));
    assertThat(canonical.get("document_number")).isEqualTo(sha256Hex("X1234567"));
    Map<String, String> exact = (Map<String, String>) rev.get("exactDigests");
    assertThat(exact.get("name")).isEqualTo(sha256Hex("Ana Example"));

    Map<String, Object> corrected = post(
        "/api/extraction/records/" + recordId + "/revisions", issuer.headers(), Map.of(
            "fields", Map.of("name", "Ana Fixed", "document_number", "X1234567",
                "date_of_birth", "1990-01-02"),
            "confidence", 0.9));
    assertThat(corrected.get("revision")).isEqualTo(2);

    Map<String, Object> approved = post(
        "/api/extraction/records/" + recordId + "/approval", issuer.headers(),
        Map.of("revision", 2));
    assertThat(approved.get("approvedRevision")).isEqualTo(2);

    Map<String, Object> reread = get("/api/extraction/records/" + recordId, issuer.headers());
    assertThat(reread.get("approvedRevision")).isEqualTo(2);
    assertThat((List<?>) reread.get("revisions")).hasSize(2);
  }

  @Test
  void staleApprovalConflicts() {
    TestAccount issuer = TestAccounts.create(owner, "ext-stale", Set.of("ISSUER_OPS"));
    FixtureSource source = storeFixture(issuer, FIXTURE);
    String recordId = runId(issuer, source);
    post("/api/extraction/records/" + recordId + "/revisions", issuer.headers(), Map.of(
        "fields", Map.of("name", "Ana Fixed"), "confidence", 0.9));
    // Revision 1 is superseded: approving it terminates instead of
    // silently re-arming the older values (AC-12).
    assertThatThrownBy(() -> post(
        "/api/extraction/records/" + recordId + "/approval", issuer.headers(),
        Map.of("revision", 1)))
        .isInstanceOf(HttpClientErrorException.Conflict.class);
  }

  @Test
  void duplicateRunConflicts() {
    TestAccount issuer = TestAccounts.create(owner, "ext-dup", Set.of("ISSUER_OPS"));
    FixtureSource source = storeFixture(issuer, FIXTURE);
    runId(issuer, source);
    assertThatThrownBy(() -> runId(issuer, source))
        .isInstanceOf(HttpClientErrorException.Conflict.class);
  }

  @Test
  void readSupportsConditionalGet() {
    TestAccount issuer = TestAccounts.create(owner, "ext-etag", Set.of("ISSUER_OPS"));
    FixtureSource source = storeFixture(issuer, FIXTURE);
    String recordId = runId(issuer, source);
    var response = client.get().uri("/api/extraction/records/" + recordId)
        .headers(issuer.headers()).retrieve().toEntity(Map.class);
    String etag = response.getHeaders().getETag();
    assertThat(etag).isNotBlank();
    var cached = client.get().uri("/api/extraction/records/" + recordId)
        .headers(issuer.headers()).header("If-None-Match", etag)
        .retrieve().toBodilessEntity();
    assertThat(cached.getStatusCode().value()).isEqualTo(304);
    // A correction changes the derived view, hence the tag: stale
    // ETags cannot mask a new revision (INV-10, SEC-39).
    post("/api/extraction/records/" + recordId + "/revisions", issuer.headers(), Map.of(
        "fields", Map.of("name", "Ana Fixed"), "confidence", 0.9));
    var reread = client.get().uri("/api/extraction/records/" + recordId)
        .headers(issuer.headers()).retrieve().toEntity(Map.class);
    assertThat(reread.getHeaders().getETag()).isNotBlank().isNotEqualTo(etag);
  }

  private record FixtureSource(String objectId, String grantId) {}

  private FixtureSource storeFixture(TestAccount issuer, String text) {
    byte[] content = text.getBytes(StandardCharsets.UTF_8);
    Map<String, Object> stored = post("/api/vault/objects", issuer.headers(), Map.of(
        "issuerId", "https://issuer.example/extraction-1",
        "displayName", "extraction source",
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
