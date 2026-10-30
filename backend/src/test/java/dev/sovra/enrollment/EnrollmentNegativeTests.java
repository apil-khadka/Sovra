package dev.sovra.enrollment;

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
 * Enrollment adversarial matrix (SOV-019, SEC-37/39/43, AC-10):
 * unreviewed sources, malformed keys and proofs, stale revisions,
 * role exclusion, and tenant isolation.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class EnrollmentNegativeTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  @Autowired ObjectMapper mapper;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
  }

  @Test
  void createOnUnapprovedExtractionConflicts() throws Exception {
    TestAccount maker = TestAccounts.create(owner, "enn-unrev", Set.of("ISSUER_OPS"));
    RawSource source = extractedSource(maker, EnrollmentFlowTests.FIXTURE);
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    // SEC-37: no extraction approval, no enrollment case.
    assertThatThrownBy(() -> post("/api/enrollments", maker.headers(), Map.of(
        "vaultObjectId", source.objectId(),
        "extractionRecordId", source.recordId(),
        "holderJwk", mapper.convertValue(holder.jwk(), Map.class))))
        .isInstanceOf(HttpClientErrorException.Conflict.class);
    assertThat(owner.queryForObject(
        "SELECT COUNT(*) FROM enrollment WHERE tenant_id = ?",
        Integer.class, maker.tenantId()))
        .isEqualTo(0);
  }

  @Test
  void createRejectsMalformedHolderKey() {
    TestAccount maker = TestAccounts.create(owner, "enn-key", Set.of("ISSUER_OPS"));
    RawSource source = extractedSource(maker, EnrollmentFlowTests.FIXTURE);
    post("/api/extraction/records/" + source.recordId() + "/approval", maker.headers(),
        Map.of("revision", 1));
    assertThatThrownBy(() -> post("/api/enrollments", maker.headers(), Map.of(
        "vaultObjectId", source.objectId(),
        "extractionRecordId", source.recordId(),
        "holderJwk", Map.of("kty", "oct", "k", "not-a-key"))))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void createRejectsMismatchedSource() throws Exception {
    TestAccount maker = TestAccounts.create(owner, "enn-mismatch", Set.of("ISSUER_OPS"));
    RawSource first = extractedSource(maker, EnrollmentFlowTests.FIXTURE);
    RawSource second = extractedSource(maker, EnrollmentFlowTests.FIXTURE);
    post("/api/extraction/records/" + first.recordId() + "/approval", maker.headers(),
        Map.of("revision", 1));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    // The extraction record belongs to the first object, not the
    // second: cross-wiring sources terminates (SEC-37).
    assertThatThrownBy(() -> post("/api/enrollments", maker.headers(), Map.of(
        "vaultObjectId", second.objectId(),
        "extractionRecordId", first.recordId(),
        "holderJwk", mapper.convertValue(holder.jwk(), Map.class))))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void approvalRequiresValidBindingProof() throws Exception {
    TestAccount maker = TestAccounts.create(owner, "enn-proof", Set.of("ISSUER_OPS"));
    TestAccount checker = TestAccounts.createInTenant(
        owner, maker.tenantId(), "enn-proof-checker", Set.of("ISSUER_OPS"));
    RawSource source = extractedSource(maker, EnrollmentFlowTests.FIXTURE);
    post("/api/extraction/records/" + source.recordId() + "/approval", maker.headers(),
        Map.of("revision", 1));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    IssuanceFixtures.HolderKeys other = IssuanceFixtures.generateHolder(mapper);
    String enrollmentId = enroll(maker, source, holder);
    post("/api/enrollments/" + enrollmentId + "/submit", maker.headers(), Map.of());

    // Missing proof.
    assertThatThrownBy(() -> post(
        "/api/enrollments/" + enrollmentId + "/decision", checker.headers(),
        Map.of("revision", 1, "decision", "approve")))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    // Proof from a key the enrollment never bound.
    String forged = IssuanceFixtures.proofOver(
        other, "enrollment-binding\n" + enrollmentId + "\n1", mapper);
    assertThatThrownBy(() -> post(
        "/api/enrollments/" + enrollmentId + "/decision", checker.headers(), Map.of(
            "revision", 1, "decision", "approve", "bindingProof", forged)))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    // Proof for the wrong revision.
    String misbound = IssuanceFixtures.proofOver(
        holder, "enrollment-binding\n" + enrollmentId + "\n2", mapper);
    assertThatThrownBy(() -> post(
        "/api/enrollments/" + enrollmentId + "/decision", checker.headers(), Map.of(
            "revision", 1, "decision", "approve", "bindingProof", misbound)))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void decideStaleRevisionConflicts() throws Exception {
    TestAccount maker = TestAccounts.create(owner, "enn-decide", Set.of("ISSUER_OPS"));
    TestAccount checker = TestAccounts.createInTenant(
        owner, maker.tenantId(), "enn-decide-checker", Set.of("ISSUER_OPS"));
    RawSource source = extractedSource(maker, EnrollmentFlowTests.FIXTURE);
    post("/api/extraction/records/" + source.recordId() + "/approval", maker.headers(),
        Map.of("revision", 1));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String enrollmentId = enroll(maker, source, holder);
    post("/api/enrollments/" + enrollmentId + "/submit", maker.headers(), Map.of());
    post("/api/extraction/records/" + source.recordId() + "/revisions", maker.headers(), Map.of(
        "fields", Map.of("name", "Ana Fixed"), "confidence", 0.9));
    post("/api/extraction/records/" + source.recordId() + "/approval", maker.headers(),
        Map.of("revision", 2));
    // The head moved to 2 while the case waited: deciding the old
    // head terminates instead of freezing stale values (SEC-39).
    assertThatThrownBy(() -> post(
        "/api/enrollments/" + enrollmentId + "/decision", checker.headers(), Map.of(
            "revision", 1, "decision", "approve",
            "bindingProof", IssuanceFixtures.proofOver(
                holder, "enrollment-binding\n" + enrollmentId + "\n1", mapper))))
        .isInstanceOf(HttpClientErrorException.Conflict.class);
  }

  @Test
  void memberCannotCreateCases() throws Exception {
    TestAccount maker = TestAccounts.create(owner, "enn-role", Set.of("ISSUER_OPS"));
    TestAccount member = TestAccounts.createInTenant(
        owner, maker.tenantId(), "enn-member", Set.of("TENANT_MEMBER"));
    RawSource source = extractedSource(maker, EnrollmentFlowTests.FIXTURE);
    post("/api/extraction/records/" + source.recordId() + "/approval", maker.headers(),
        Map.of("revision", 1));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    assertThatThrownBy(() -> post("/api/enrollments", member.headers(), Map.of(
        "vaultObjectId", source.objectId(),
        "extractionRecordId", source.recordId(),
        "holderJwk", mapper.convertValue(holder.jwk(), Map.class))))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
  }

  @Test
  void crossTenantReadIsNotFound() throws Exception {
    TestAccount maker = TestAccounts.create(owner, "enn-tenant", Set.of("ISSUER_OPS"));
    RawSource source = extractedSource(maker, EnrollmentFlowTests.FIXTURE);
    post("/api/extraction/records/" + source.recordId() + "/approval", maker.headers(),
        Map.of("revision", 1));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String enrollmentId = enroll(maker, source, holder);
    TestAccount stranger = TestAccounts.create(owner, "enn-stranger", Set.of("ISSUER_OPS"));
    assertThatThrownBy(() -> client.get().uri("/api/enrollments/" + enrollmentId)
        .headers(stranger.headers()).retrieve().body(Map.class))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
  }

  @Test
  void submitCurrentApprovalConflicts() throws Exception {
    TestAccount maker = TestAccounts.create(owner, "enn-submit", Set.of("ISSUER_OPS"));
    TestAccount checker = TestAccounts.createInTenant(
        owner, maker.tenantId(), "enn-submit-checker", Set.of("ISSUER_OPS"));
    RawSource source = extractedSource(maker, EnrollmentFlowTests.FIXTURE);
    post("/api/extraction/records/" + source.recordId() + "/approval", maker.headers(),
        Map.of("revision", 1));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String enrollmentId = enroll(maker, source, holder);
    post("/api/enrollments/" + enrollmentId + "/submit", maker.headers(), Map.of());
    post("/api/enrollments/" + enrollmentId + "/decision", checker.headers(), Map.of(
        "revision", 1, "decision", "approve",
        "bindingProof", IssuanceFixtures.proofOver(
            holder, "enrollment-binding\n" + enrollmentId + "\n1", mapper)));
    // Current approvals stay put; re-review needs a stale source.
    assertThatThrownBy(
        () -> post("/api/enrollments/" + enrollmentId + "/submit", maker.headers(), Map.of()))
        .isInstanceOf(HttpClientErrorException.Conflict.class);
  }

  private String enroll(
      TestAccount maker, RawSource source, IssuanceFixtures.HolderKeys holder) {
    Map<String, Object> created = post("/api/enrollments", maker.headers(), Map.of(
        "vaultObjectId", source.objectId(),
        "extractionRecordId", source.recordId(),
        "holderJwk", mapper.convertValue(holder.jwk(), Map.class)));
    return created.get("enrollmentId").toString();
  }

  private record RawSource(String objectId, String recordId) {}

  private RawSource extractedSource(TestAccount maker, String text) {
    byte[] content = text.getBytes(StandardCharsets.UTF_8);
    Map<String, Object> stored = post("/api/vault/objects", maker.headers(), Map.of(
        "issuerId", "https://issuer.example/enrollment-neg",
        "displayName", "enrollment source",
        "purposes", List.of("extraction-run"),
        "contentBase64", Base64.getEncoder().encodeToString(content),
        "contentSha256Hex", sha256Hex(text)));
    String objectId = stored.get("objectId").toString();
    Map<String, Object> granted = post("/api/vault/grants", maker.headers(), Map.of(
        "objectId", objectId,
        "objectVersion", 1,
        "principalType", "service_account",
        "principalId", maker.accountId().toString(),
        "purpose", "extraction-run",
        "workload", "sovra-test",
        "ttlSeconds", 3600));
    Map<String, Object> run = post("/api/extraction/records", maker.headers(), Map.of(
        "vaultObjectId", objectId,
        "objectVersion", 1,
        "grantId", granted.get("grantId").toString(),
        "purpose", "extraction-run",
        "workload", "sovra-test",
        "schemaId", "fixture-doc-v1"));
    return new RawSource(objectId, run.get("recordId").toString());
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
