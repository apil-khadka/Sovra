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
 * Extraction adversarial matrix (SOV-018, SEC-36..40, AC-10):
 * wrong-source termination, role exclusion, tenant isolation, and
 * malformed corrections and approvals.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ExtractionNegativeTests extends SovraAppRoleBase {

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
  void wrongSourceTerminatesRun() {
    TestAccount issuer = TestAccounts.create(owner, "exn-src", Set.of("ISSUER_OPS"));
    GrantedSource source = store(issuer, "plain bytes, not a fixture");
    // AC-10: input the engine does not recognize ends the run with
    // no record, not a partial guess.
    assertThatThrownBy(() -> run(issuer, source, "fixture-doc-v1"))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    assertThat(owner.queryForObject(
        "SELECT COUNT(*) FROM extraction_record WHERE tenant_id = ?",
        Integer.class, issuer.tenantId()))
        .isEqualTo(0);
  }

  @Test
  void unknownSchemaTerminatesRun() {
    TestAccount issuer = TestAccounts.create(owner, "exn-schema", Set.of("ISSUER_OPS"));
    GrantedSource source = store(issuer, ExtractionFlowTests.FIXTURE);
    assertThatThrownBy(() -> run(issuer, source, "other-schema"))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void memberCannotRunEvenWithGrant() {
    TestAccount issuer = TestAccounts.create(owner, "exn-role", Set.of("ISSUER_OPS"));
    TestAccount member = TestAccounts.createInTenant(
        owner, issuer.tenantId(), "exn-member", Set.of("TENANT_MEMBER"));
    GrantedSource source = storeGrantedTo(issuer, member, ExtractionFlowTests.FIXTURE);
    // The member holds a valid vault grant, so the 403 proves the
    // EXTRACTION_RUN role rule fired — not the vault layer.
    assertThatThrownBy(() -> run(member, source, "fixture-doc-v1"))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
  }

  @Test
  void crossTenantReadIsNotFound() {
    TestAccount issuer = TestAccounts.create(owner, "exn-tenant", Set.of("ISSUER_OPS"));
    GrantedSource source = store(issuer, ExtractionFlowTests.FIXTURE);
    String recordId = run(issuer, source, "fixture-doc-v1");
    TestAccount stranger = TestAccounts.create(owner, "exn-stranger", Set.of("ISSUER_OPS"));
    assertThatThrownBy(() -> client.get().uri("/api/extraction/records/" + recordId)
        .headers(stranger.headers()).retrieve().body(Map.class))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
  }

  @Test
  void anonymousReadIsUnauthorized() {
    TestAccount issuer = TestAccounts.create(owner, "exn-anon", Set.of("ISSUER_OPS"));
    GrantedSource source = store(issuer, ExtractionFlowTests.FIXTURE);
    String recordId = run(issuer, source, "fixture-doc-v1");
    assertThatThrownBy(() -> client.get().uri("/api/extraction/records/" + recordId)
        .retrieve().body(Map.class))
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
  }

  @Test
  void unknownRevisionApprovalTerminates() {
    TestAccount issuer = TestAccounts.create(owner, "exn-rev", Set.of("ISSUER_OPS"));
    GrantedSource source = store(issuer, ExtractionFlowTests.FIXTURE);
    String recordId = run(issuer, source, "fixture-doc-v1");
    assertThatThrownBy(() -> post(
        "/api/extraction/records/" + recordId + "/approval", issuer.headers(),
        Map.of("revision", 7)))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void malformedCorrectionsTerminate() {
    TestAccount issuer = TestAccounts.create(owner, "exn-corr", Set.of("ISSUER_OPS"));
    GrantedSource source = store(issuer, ExtractionFlowTests.FIXTURE);
    String recordId = run(issuer, source, "fixture-doc-v1");
    String uri = "/api/extraction/records/" + recordId + "/revisions";
    assertThatThrownBy(() -> post(uri, issuer.headers(), Map.of(
        "fields", Map.of(), "confidence", 0.9)))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    assertThatThrownBy(() -> post(uri, issuer.headers(), Map.of(
        "fields", Map.of("name", "Ana"), "confidence", 1.5)))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    assertThatThrownBy(() -> post(uri, issuer.headers(), Map.of(
        "fields", Map.of("name", ""), "confidence", 0.9)))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  private record GrantedSource(String objectId, String grantId) {}

  private GrantedSource store(TestAccount issuer, String text) {
    return storeGrantedTo(issuer, issuer, text);
  }

  private GrantedSource storeGrantedTo(TestAccount issuer, TestAccount grantee, String text) {
    byte[] content = text.getBytes(StandardCharsets.UTF_8);
    Map<String, Object> stored = post("/api/vault/objects", issuer.headers(), Map.of(
        "issuerId", "https://issuer.example/extraction-neg",
        "displayName", "negative source",
        "purposes", List.of("extraction-run"),
        "contentBase64", Base64.getEncoder().encodeToString(content),
        "contentSha256Hex", sha256Hex(text)));
    String objectId = stored.get("objectId").toString();
    Map<String, Object> granted = post("/api/vault/grants", issuer.headers(), Map.of(
        "objectId", objectId,
        "objectVersion", 1,
        "principalType", "service_account",
        "principalId", grantee.accountId().toString(),
        "purpose", "extraction-run",
        "workload", "sovra-test",
        "ttlSeconds", 3600));
    return new GrantedSource(objectId, granted.get("grantId").toString());
  }

  private String run(TestAccount caller, GrantedSource source, String schemaId) {
    Map<String, Object> run = post("/api/extraction/records", caller.headers(), Map.of(
        "vaultObjectId", source.objectId(),
        "objectVersion", 1,
        "grantId", source.grantId(),
        "purpose", "extraction-run",
        "workload", "sovra-test",
        "schemaId", schemaId));
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

  private Map<String, Object> post(
      String uri, Consumer<HttpHeaders> headers, Map<String, Object> body) {
    return client.post().uri(uri).headers(headers).body(body).retrieve().body(Map.class);
  }
}
