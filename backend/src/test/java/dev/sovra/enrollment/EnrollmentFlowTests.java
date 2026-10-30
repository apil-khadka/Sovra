package dev.sovra.enrollment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Enrollment happy paths (SOV-019, OD-14, FR-37/39): maker/checker
 * cases to approval, stale-source re-review, rejection
 * attribution, and enrollment-bound issuance through the
 * constrained signer.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class EnrollmentFlowTests extends SovraAppRoleBase {

  static final String FIXTURE =
      "SOVRA-FIXTURE/v1\n"
          + "name: Ana Example\n"
          + "document_number: X1234567\n"
          + "date_of_birth: 1990-01-02\n"
          + "country: NL\n";

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

  @Test
  @SuppressWarnings("unchecked")
  void makerCheckerCaseToApproval() throws Exception {
    TestAccount maker = TestAccounts.create(owner, "enr-maker", Set.of("ISSUER_OPS"));
    TestAccount checker = TestAccounts.createInTenant(
        owner, maker.tenantId(), "enr-checker", Set.of("ISSUER_OPS"));
    ApprovedSource source = approvedSource(maker, FIXTURE);
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);

    Map<String, Object> created = post("/api/enrollments", maker.headers(), Map.of(
        "vaultObjectId", source.objectId(),
        "extractionRecordId", source.recordId(),
        "holderJwk", mapper.convertValue(holder.jwk(), Map.class)));
    String enrollmentId = created.get("enrollmentId").toString();
    // Opaque local identifiers (FR-34): both parse as UUIDs, carry
    // no PII, and differ from each other.
    UUID subjectRef = UUID.fromString(created.get("subjectRef").toString());
    assertThat(subjectRef.toString()).isNotEqualTo(enrollmentId);
    assertThat(created.get("state")).isEqualTo("PENDING");

    Map<String, Object> submitted =
        post("/api/enrollments/" + enrollmentId + "/submit", maker.headers(), Map.of());
    assertThat(submitted.get("state")).isEqualTo("IN_REVIEW");

    Map<String, Object> decided = post(
        "/api/enrollments/" + enrollmentId + "/decision", checker.headers(), Map.of(
            "revision", 1, "decision", "approve",
            "bindingProof", bindingProof(holder, enrollmentId, 1)));
    assertThat(decided.get("state")).isEqualTo("APPROVED");
    assertThat(decided.get("boundRevision")).isEqualTo(1);

    Map<String, Object> read = get("/api/enrollments/" + enrollmentId, maker.headers());
    assertThat(read.get("state")).isEqualTo("APPROVED");
    assertThat(read.get("eligible")).isEqualTo(Boolean.TRUE);
    assertThat(read.get("eligibilityReason")).isEqualTo("CURRENT");
    assertThat(read.get("createdBy")).isEqualTo("enr-maker");
    assertThat(read.get("decidedBy")).isEqualTo("enr-checker");
    List<Map<String, Object>> reviews = (List<Map<String, Object>>) read.get("reviews");
    assertThat(reviews).hasSize(1);
    assertThat(reviews.get(0).get("bindingProofOk")).isEqualTo(Boolean.TRUE);

    Map<String, Object> eligibility =
        get("/api/enrollments/" + enrollmentId + "/eligibility", maker.headers());
    assertThat(eligibility.get("eligible")).isEqualTo(Boolean.TRUE);
    Map<String, String> claims = (Map<String, String>) eligibility.get("claims");
    assertThat(claims.get("name")).isEqualTo("ana example");
    assertThat(claims.get("adultOver18")).isEqualTo("true");
  }

  @Test
  void selfApprovalConflicts() throws Exception {
    TestAccount maker = TestAccounts.create(owner, "enr-self", Set.of("ISSUER_OPS"));
    ApprovedSource source = approvedSource(maker, FIXTURE);
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String enrollmentId = enroll(maker, source, holder);
    post("/api/enrollments/" + enrollmentId + "/submit", maker.headers(), Map.of());
    // OD-14: the identity that built the case cannot approve it,
    // even with a valid holder binding proof.
    assertThatThrownBy(() -> post(
        "/api/enrollments/" + enrollmentId + "/decision", maker.headers(), Map.of(
            "revision", 1, "decision", "approve",
            "bindingProof", bindingProof(holder, enrollmentId, 1))))
        .isInstanceOf(HttpClientErrorException.Conflict.class);
  }

  @Test
  @SuppressWarnings("unchecked")
  void staleSourceRequiresRereview() throws Exception {
    TestAccount maker = TestAccounts.create(owner, "enr-stale", Set.of("ISSUER_OPS"));
    TestAccount checker = TestAccounts.createInTenant(
        owner, maker.tenantId(), "enr-stale-checker", Set.of("ISSUER_OPS"));
    ApprovedSource source = approvedSource(maker, FIXTURE);
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String enrollmentId = enroll(maker, source, holder);
    post("/api/enrollments/" + enrollmentId + "/submit", maker.headers(), Map.of());
    post("/api/enrollments/" + enrollmentId + "/decision", checker.headers(), Map.of(
        "revision", 1, "decision", "approve",
        "bindingProof", bindingProof(holder, enrollmentId, 1)));

    // A correction plus a new extraction approval moves the head:
    // the bound revision is now stale (AC-11, INV-10).
    post("/api/extraction/records/" + source.recordId() + "/revisions", maker.headers(), Map.of(
        "fields", Map.of("name", "Ana Fixed", "document_number", "X1234567",
            "date_of_birth", "1990-01-02"),
        "confidence", 0.9));
    post("/api/extraction/records/" + source.recordId() + "/approval", maker.headers(),
        Map.of("revision", 2));
    Map<String, Object> stale =
        get("/api/enrollments/" + enrollmentId + "/eligibility", maker.headers());
    assertThat(stale.get("eligible")).isEqualTo(Boolean.FALSE);
    assertThat(stale.get("reason")).isEqualTo("STALE_SOURCE");

    // Explicit refresh: re-submit, then re-approve the new head.
    post("/api/enrollments/" + enrollmentId + "/submit", maker.headers(), Map.of());
    Map<String, Object> redecided = post(
        "/api/enrollments/" + enrollmentId + "/decision", checker.headers(), Map.of(
            "revision", 2, "decision", "approve",
            "bindingProof", bindingProof(holder, enrollmentId, 2)));
    assertThat(redecided.get("state")).isEqualTo("APPROVED");
    assertThat(redecided.get("boundRevision")).isEqualTo(2);
    Map<String, Object> reread = get("/api/enrollments/" + enrollmentId, maker.headers());
    assertThat(reread.get("eligible")).isEqualTo(Boolean.TRUE);
    assertThat((List<?>) reread.get("reviews")).hasSize(2);
  }

  @Test
  void enrollmentBoundIssuanceSignsReviewedClaims() throws Exception {
    TestAccount maker = TestAccounts.create(owner, "enr-issue", Set.of("ISSUER_OPS"));
    TestAccount checker = TestAccounts.createInTenant(
        owner, maker.tenantId(), "enr-issue-checker", Set.of("ISSUER_OPS"));
    ApprovedSource source = approvedSource(maker, FIXTURE);
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String enrollmentId = enroll(maker, source, holder);
    post("/api/enrollments/" + enrollmentId + "/submit", maker.headers(), Map.of());
    post("/api/enrollments/" + enrollmentId + "/decision", checker.headers(), Map.of(
        "revision", 1, "decision", "approve",
        "bindingProof", bindingProof(holder, enrollmentId, 1)));

    String key = "enr-issue-" + UUID.randomUUID();
    Map<String, Object> body = issueBody(holder, key);
    body.put("enrollmentId", enrollmentId);
    String raw = issueRaw(maker, key, body);
    Map<String, Object> response = mapper.readValue(raw, Map.class);
    assertThat(response.get("status")).isEqualTo("VALID");
    String jwks = client.get().uri("/api/issuance/jwks.json").retrieve().body(String.class);
    IssuanceFixtures.VerifiedArtifact verified =
        IssuanceFixtures.verify(response.get("artifact").toString(), jwks, mapper);
    assertThat(verified.claims().get("vct").asString()).isEqualTo(IssuanceFixtures.ADULT_VCT);
  }

  @Test
  void issuanceRejectsUnreviewedStaleAndSubstitutedEnrollment() throws Exception {
    TestAccount maker = TestAccounts.create(owner, "enr-neg", Set.of("ISSUER_OPS"));
    TestAccount checker = TestAccounts.createInTenant(
        owner, maker.tenantId(), "enr-neg-checker", Set.of("ISSUER_OPS"));
    ApprovedSource source = approvedSource(maker, FIXTURE);
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    IssuanceFixtures.HolderKeys stranger = IssuanceFixtures.generateHolder(mapper);
    String enrollmentId = enroll(maker, source, holder);
    post("/api/enrollments/" + enrollmentId + "/submit", maker.headers(), Map.of());
    post("/api/enrollments/" + enrollmentId + "/decision", checker.headers(), Map.of(
        "revision", 1, "decision", "approve",
        "bindingProof", bindingProof(holder, enrollmentId, 1)));

    // Caller-supplied value under a reviewed key: the reviewed name
    // is "ana example", not "mallory" (FR-39).
    String forgedKey = "enr-forged-" + UUID.randomUUID();
    Map<String, Object> forged = issueBody(holder, forgedKey);
    forged.put("enrollmentId", enrollmentId);
    forged.put("claims", Map.of("adultOver18", Boolean.TRUE, "name", "mallory"));
    assertThatThrownBy(() -> issueRaw(maker, forgedKey, forged))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);

    // Key substitution: a valid proof from a key the enrollment
    // never bound (FR-37).
    String swappedKey = "enr-swapped-" + UUID.randomUUID();
    Map<String, Object> swapped = issueBody(stranger, swappedKey);
    swapped.put("enrollmentId", enrollmentId);
    assertThatThrownBy(() -> issueRaw(maker, swappedKey, swapped))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);

    // Stale approval after the source moves on (AC-11).
    post("/api/extraction/records/" + source.recordId() + "/revisions", maker.headers(), Map.of(
        "fields", Map.of("name", "Ana Fixed"), "confidence", 0.9));
    post("/api/extraction/records/" + source.recordId() + "/approval", maker.headers(),
        Map.of("revision", 2));
    String staleKey = "enr-staleissue-" + UUID.randomUUID();
    Map<String, Object> stale = issueBody(holder, staleKey);
    stale.put("enrollmentId", enrollmentId);
    assertThatThrownBy(() -> issueRaw(maker, staleKey, stale))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  @SuppressWarnings("unchecked")
  void rejectionIsTerminalAndAttributable() throws Exception {
    TestAccount maker = TestAccounts.create(owner, "enr-rej", Set.of("ISSUER_OPS"));
    TestAccount checker = TestAccounts.createInTenant(
        owner, maker.tenantId(), "enr-rej-checker", Set.of("ISSUER_OPS"));
    ApprovedSource source = approvedSource(maker, FIXTURE);
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String enrollmentId = enroll(maker, source, holder);
    post("/api/enrollments/" + enrollmentId + "/submit", maker.headers(), Map.of());
    Map<String, Object> decided = post(
        "/api/enrollments/" + enrollmentId + "/decision", checker.headers(),
        Map.of("revision", 1, "decision", "reject"));
    assertThat(decided.get("state")).isEqualTo("REJECTED");
    // Rejected cases stay rejected: a new enrollment starts over.
    assertThatThrownBy(
        () -> post("/api/enrollments/" + enrollmentId + "/submit", maker.headers(), Map.of()))
        .isInstanceOf(HttpClientErrorException.Conflict.class);
    Map<String, Object> read = get("/api/enrollments/" + enrollmentId, maker.headers());
    assertThat(read.get("eligible")).isEqualTo(Boolean.FALSE);
    List<Map<String, Object>> reviews = (List<Map<String, Object>>) read.get("reviews");
    assertThat(reviews).hasSize(1);
    assertThat(reviews.get(0).get("decision")).isEqualTo("REJECTED");
    assertThat(reviews.get(0).get("bindingProofOk")).isEqualTo(Boolean.FALSE);
    assertThat(reviews.get(0).get("reviewer")).isEqualTo("enr-rej-checker");
  }

  private String bindingProof(
      IssuanceFixtures.HolderKeys holder, String enrollmentId, int revision) throws Exception {
    return IssuanceFixtures.proofOver(
        holder, "enrollment-binding\n" + enrollmentId + "\n" + revision, mapper);
  }

  private String enroll(
      TestAccount maker, ApprovedSource source, IssuanceFixtures.HolderKeys holder) {
    Map<String, Object> created = post("/api/enrollments", maker.headers(), Map.of(
        "vaultObjectId", source.objectId(),
        "extractionRecordId", source.recordId(),
        "holderJwk", mapper.convertValue(holder.jwk(), Map.class)));
    return created.get("enrollmentId").toString();
  }

  private record ApprovedSource(String objectId, String recordId) {}

  private ApprovedSource approvedSource(TestAccount maker, String text) {
    byte[] content = text.getBytes(StandardCharsets.UTF_8);
    Map<String, Object> stored = post("/api/vault/objects", maker.headers(), Map.of(
        "issuerId", "https://issuer.example/enrollment-1",
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
    String recordId = run.get("recordId").toString();
    post("/api/extraction/records/" + recordId + "/approval", maker.headers(),
        Map.of("revision", 1));
    return new ApprovedSource(objectId, recordId);
  }

  private Map<String, Object> issueBody(IssuanceFixtures.HolderKeys holder, String key)
      throws Exception {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("issuerId", IssuanceFixtures.ISSUER_ID);
    body.put("vct", IssuanceFixtures.ADULT_VCT);
    body.put("holderJwk", mapper.convertValue(holder.jwk(), Map.class));
    body.put("holderProof",
        IssuanceFixtures.proof(holder, key, IssuanceFixtures.ADULT_VCT, mapper));
    body.put("claims", Map.of("adultOver18", Boolean.TRUE));
    body.put("expiresAt", Instant.now().plusSeconds(3600).toString());
    return body;
  }

  private String issueRaw(TestAccount issuer, String key, Map<String, Object> body) {
    return client.post().uri("/api/issuance/credentials")
        .headers(h -> {
          issuer.headers().accept(h);
          h.set("Idempotency-Key", key);
        })
        .contentType(MediaType.APPLICATION_JSON)
        .body(body)
        .retrieve()
        .body(String.class);
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
