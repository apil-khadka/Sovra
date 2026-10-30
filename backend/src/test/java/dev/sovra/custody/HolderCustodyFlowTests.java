package dev.sovra.custody;

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
 * Custody happy paths (SOV-020, OD-09): loss report revokes at
 * once, recovery activates a fresh proven key, compromised keys
 * lose issuance, and revoked credentials stay revoked while
 * reissuance mints new ids.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class HolderCustodyFlowTests extends SovraAppRoleBase {

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
  void lossReportRecoveryRoundTrip() throws Exception {
    TestAccount ops = TestAccounts.create(owner, "cus-ops", Set.of("ISSUER_OPS"));
    TestAccount admin = TestAccounts.createInTenant(
        owner, ops.tenantId(), "cus-admin", Set.of("TRUST_ADMIN"));
    Case Case = approvedCase(ops, FIXTURE);
    IssuanceFixtures.HolderKeys fresh = IssuanceFixtures.generateHolder(mapper);

    // A credential exists before the loss.
    String firstCredential = issue(ops, Case, Case.holder());
    assertThat(credentialStatus(firstCredential)).isEqualTo("VALID");

    // Report: the key flips and its credential dies at once.
    Map<String, Object> reported = post("/api/holder-keys/report", ops.headers(), Map.of(
        "thumbprint", IssuanceFixtures.thumbprint(Case.holder()), "reason", "loss"));
    String recoveryId = reported.get("recoveryId").toString();
    assertThat(reported.get("revokedCredentials")).isEqualTo(1);
    assertThat(credentialStatus(firstCredential)).isEqualTo("REVOKED");
    Map<String, Object> keyed =
        get("/api/holder-keys/" + reported.get("keyId"), ops.headers());
    assertThat(keyed.get("status")).isEqualTo("COMPROMISED");
    assertThat(keyed.toString()).doesNotContain("\"d\"");

    // Recovery under a trust admin with a fresh-key proof.
    Map<String, Object> recovered = post("/api/holder-keys/recover", admin.headers(), Map.of(
        "recoveryId", recoveryId,
        "newHolderJwk", mapper.convertValue(fresh.jwk(), Map.class),
        "newKeyProof", recoveryProof(fresh, recoveryId)));
    assertThat(recovered.get("newThumbprint"))
        .isEqualTo(IssuanceFixtures.thumbprint(fresh));
    Map<String, Object> reread =
        get("/api/holder-keys/" + reported.get("keyId"), ops.headers());
    List<Map<String, Object>> recoveries =
        (List<Map<String, Object>>) reread.get("recoveries");
    assertThat(recoveries).hasSize(1);
    assertThat(recoveries.get(0).get("state")).isEqualTo("RECOVERED");

    // Reissuance under the new key mints a new credential id.
    String secondCredential = issue(ops, Case, fresh);
    assertThat(secondCredential).isNotEqualTo(firstCredential);
    assertThat(credentialStatus(secondCredential)).isEqualTo("VALID");
    assertThat(credentialStatus(firstCredential)).isEqualTo("REVOKED");
  }

  @Test
  void compromisedKeyLosesIssuance() throws Exception {
    TestAccount ops = TestAccounts.create(owner, "cus-comp", Set.of("ISSUER_OPS"));
    Case Case = approvedCase(ops, FIXTURE);
    post("/api/holder-keys/report", ops.headers(), Map.of(
        "thumbprint", IssuanceFixtures.thumbprint(Case.holder()), "reason", "theft"));
    // Before recovery completes, the compromised key authorizes
    // nothing (SOV-020 scenario 2).
    assertThatThrownBy(() -> issue(ops, Case, Case.holder()))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void rereviewAfterRecoveryKeepsRecoveredKey() throws Exception {
    TestAccount ops = TestAccounts.create(owner, "cus-keep", Set.of("ISSUER_OPS"));
    TestAccount admin = TestAccounts.createInTenant(
        owner, ops.tenantId(), "cus-keep-admin", Set.of("TRUST_ADMIN"));
    SourceIds src = recordIdFor(ops, FIXTURE);
    String recordId = src.recordId();
    Case Case = approvedCaseOnRecord(ops, recordId);
    IssuanceFixtures.HolderKeys fresh = IssuanceFixtures.generateHolder(mapper);
    Map<String, Object> reported = post("/api/holder-keys/report", ops.headers(), Map.of(
        "thumbprint", IssuanceFixtures.thumbprint(Case.holder()), "reason", "loss"));
    post("/api/holder-keys/recover", admin.headers(), Map.of(
        "recoveryId", reported.get("recoveryId").toString(),
        "newHolderJwk", mapper.convertValue(fresh.jwk(), Map.class),
        "newKeyProof", recoveryProof(fresh, reported.get("recoveryId").toString())));
    // The source moves on after recovery: re-approval must keep
    // the recovered key, never resurrect the compromised one.
    TestAccount checker = TestAccounts.createInTenant(
        owner, ops.tenantId(), "cus-keep-checker", Set.of("ISSUER_OPS"));
    post("/api/extraction/records/" + recordId + "/revisions", ops.headers(), Map.of(
        "fields", Map.of("name", "Ana Fixed", "document_number", "X1234567",
            "date_of_birth", "1990-01-02"),
        "confidence", 0.9));
    post("/api/extraction/records/" + recordId + "/approval", ops.headers(),
        Map.of("revision", 2));
    post("/api/enrollments/" + Case.enrollmentId() + "/submit", ops.headers(), Map.of());
    post("/api/enrollments/" + Case.enrollmentId() + "/decision", checker.headers(), Map.of(
        "revision", 2, "decision", "approve",
        "bindingProof", IssuanceFixtures.proofOver(
            Case.holder(),
            "enrollment-binding\n" + Case.enrollmentId() + "\n2", mapper)));
    // The recovered key issues; the compromised original does not.
    assertThat(issue(ops, Case, fresh)).isNotBlank();
    assertThatThrownBy(() -> issue(ops, Case, Case.holder()))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void revokedCredentialsStayRevoked() throws Exception {
    TestAccount ops = TestAccounts.create(owner, "cus-rev", Set.of("ISSUER_OPS"));
    TestAccount admin = TestAccounts.createInTenant(
        owner, ops.tenantId(), "cus-rev-admin", Set.of("TRUST_ADMIN"));
    Case Case = approvedCase(ops, FIXTURE);
    IssuanceFixtures.HolderKeys fresh = IssuanceFixtures.generateHolder(mapper);
    String oldCredential = issue(ops, Case, Case.holder());
    Map<String, Object> reported = post("/api/holder-keys/report", ops.headers(), Map.of(
        "thumbprint", IssuanceFixtures.thumbprint(Case.holder()), "reason", "compromise"));
    post("/api/holder-keys/recover", admin.headers(), Map.of(
        "recoveryId", reported.get("recoveryId").toString(),
        "newHolderJwk", mapper.convertValue(fresh.jwk(), Map.class),
        "newKeyProof", recoveryProof(fresh, reported.get("recoveryId").toString())));
    // Recovery never resurrects: the old id stays REVOKED and the
    // status endpoint keeps saying so.
    assertThat(credentialStatus(oldCredential)).isEqualTo("REVOKED");
    Map<String, Object> status = get(
        "/api/issuance/credentials/" + oldCredential + "/status", ops.headers());
    assertThat(status.get("status")).isEqualTo("REVOKED");
  }

  private String recoveryProof(IssuanceFixtures.HolderKeys fresh, String recoveryId)
      throws Exception {
    return IssuanceFixtures.proofOver(
        fresh,
        "holder-recovery\n" + recoveryId + "\n" + IssuanceFixtures.thumbprint(fresh),
        mapper);
  }

  private record Case(String enrollmentId, IssuanceFixtures.HolderKeys holder) {}

  private record SourceIds(String objectId, String recordId) {}

  private Case approvedCase(TestAccount ops, String text) throws Exception {
    TestAccount checker = TestAccounts.createInTenant(
        owner, ops.tenantId(), "cus-checker-" + UUID.randomUUID().toString().substring(0, 8),
        Set.of("ISSUER_OPS"));
    SourceIds source = recordIdFor(ops, text);
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    return approvedCaseOnRecord(ops, checker, source, holder);
  }

  private Case approvedCaseOnRecord(TestAccount ops, String recordId) throws Exception {
    TestAccount checker = TestAccounts.createInTenant(
        owner, ops.tenantId(), "cus-checker-" + UUID.randomUUID().toString().substring(0, 8),
        Set.of("ISSUER_OPS"));
    String objectId = owner.queryForObject(
        "SELECT vault_object_id::text FROM extraction_record WHERE id = ?",
        String.class, UUID.fromString(recordId));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    return approvedCaseOnRecord(ops, checker, new SourceIds(objectId, recordId), holder);
  }

  private Case approvedCaseOnRecord(
      TestAccount ops, TestAccount checker, SourceIds source,
      IssuanceFixtures.HolderKeys holder) throws Exception {
    Map<String, Object> created = post("/api/enrollments", ops.headers(), Map.of(
        "vaultObjectId", source.objectId(), "extractionRecordId", source.recordId(),
        "holderJwk", mapper.convertValue(holder.jwk(), Map.class)));
    String enrollmentId = created.get("enrollmentId").toString();
    post("/api/enrollments/" + enrollmentId + "/submit", ops.headers(), Map.of());
    post("/api/enrollments/" + enrollmentId + "/decision", checker.headers(), Map.of(
        "revision", 1, "decision", "approve",
        "bindingProof", IssuanceFixtures.proofOver(
            holder, "enrollment-binding\n" + enrollmentId + "\n1", mapper)));
    return new Case(enrollmentId, holder);
  }

  private SourceIds recordIdFor(TestAccount ops, String text) {
    byte[] content = text.getBytes(StandardCharsets.UTF_8);
    Map<String, Object> stored = post("/api/vault/objects", ops.headers(), Map.of(
        "issuerId", "https://issuer.example/custody-1",
        "displayName", "custody source",
        "purposes", List.of("extraction-run"),
        "contentBase64", Base64.getEncoder().encodeToString(content),
        "contentSha256Hex", sha256Hex(text)));
    String objectId = stored.get("objectId").toString();
    Map<String, Object> granted = post("/api/vault/grants", ops.headers(), Map.of(
        "objectId", objectId, "objectVersion", 1, "principalType", "service_account",
        "principalId", ops.accountId().toString(), "purpose", "extraction-run",
        "workload", "sovra-test", "ttlSeconds", 3600));
    Map<String, Object> run = post("/api/extraction/records", ops.headers(), Map.of(
        "vaultObjectId", objectId, "objectVersion", 1,
        "grantId", granted.get("grantId").toString(), "purpose", "extraction-run",
        "workload", "sovra-test", "schemaId", "fixture-doc-v1"));
    String recordId = run.get("recordId").toString();
    post("/api/extraction/records/" + recordId + "/approval", ops.headers(),
        Map.of("revision", 1));
    return new SourceIds(objectId, recordId);
  }

  private String issue(TestAccount ops, Case Case, IssuanceFixtures.HolderKeys holder)
      throws Exception {
    String key = "cus-" + UUID.randomUUID();
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("issuerId", IssuanceFixtures.ISSUER_ID);
    body.put("vct", IssuanceFixtures.ADULT_VCT);
    body.put("holderJwk", mapper.convertValue(holder.jwk(), Map.class));
    body.put("holderProof",
        IssuanceFixtures.proof(holder, key, IssuanceFixtures.ADULT_VCT, mapper));
    body.put("claims", Map.of("adultOver18", Boolean.TRUE));
    body.put("expiresAt", Instant.now().plusSeconds(3600).toString());
    body.put("enrollmentId", Case.enrollmentId());
    String raw = client.post().uri("/api/issuance/credentials")
        .headers(h -> {
          ops.headers().accept(h);
          h.set("Idempotency-Key", key);
        })
        .contentType(MediaType.APPLICATION_JSON)
        .body(body)
        .retrieve()
        .body(String.class);
    return mapper.readValue(raw, Map.class).get("credentialId").toString();
  }

  private String credentialStatus(String credentialId) {
    return owner.queryForObject(
        "SELECT status FROM credential_artifact WHERE id = ?", String.class,
        UUID.fromString(credentialId));
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
