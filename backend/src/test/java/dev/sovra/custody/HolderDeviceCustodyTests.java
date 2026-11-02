package dev.sovra.custody;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.consent.ConsentFixtures;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import dev.sovra.verification.VerificationFixtures;
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
 * Durable device custody exercise (PROD-015): theft reported
 * against the device kills every credential its keys authorize;
 * trust-admin recovery re-keys onto a named replacement device;
 * issuer-ops reissuance replaces exactly the report-linked
 * credentials under fresh holder proofs. Wrong-holder, revoked,
 * and expired presentations fail with their own reason codes —
 * never by resurrecting a revoked id.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class HolderDeviceCustodyTests extends SovraAppRoleBase {

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
  void deviceTheftToReissueRoundTrip() throws Exception {
    Parties parties =
        Parties.create(owner, "dev-full");
    Case Case = approvedCase(parties.ops(), FIXTURE);

    // Approval mints the primary device and binds the case key.
    UUID primary = deviceId(Case.enrollmentId(), "primary");
    assertThat(keyDevice(Case.enrollmentId())).isEqualTo(primary);

    String first = issue(parties.ops(), Case, Case.holder());
    String second = issue(parties.ops(), Case, Case.holder());
    String firstRequest = approvedRequest(parties, first, Case.holder());
    assertThat(present(parties, firstRequest, Case.holder()).get("outcome"))
        .isEqualTo("ACCEPTED");

    // Theft against the device: one case, both credentials dead.
    Map<String, Object> deviceReport = post(
        "/api/holder-devices/report",
        parties.ops().headers(),
        Map.of("deviceId", primary.toString(), "reason", "theft"));
    assertThat(deviceReport.get("status")).isEqualTo("STOLEN");
    assertThat(deviceReport.get("revokedCredentials")).isEqualTo(2);
    List<Map<String, Object>> cases = (List<Map<String, Object>>) deviceReport.get("cases");
    assertThat(cases).hasSize(1);
    String recoveryId = cases.get(0).get("recoveryId").toString();
    assertThat(credentialStatus(first)).isEqualTo("REVOKED");
    assertThat(credentialStatus(second)).isEqualTo("REVOKED");
    // A fresh nonce proves revocation, not replay.
    assertThat(present(parties, firstRequest, Case.holder()))
        .containsEntry("outcome", "REJECTED")
        .containsEntry("reasonCode", "CREDENTIAL_REVOKED");

    // Recovery re-keys onto the named replacement device.
    IssuanceFixtures.HolderKeys fresh = IssuanceFixtures.generateHolder(mapper);
    post(
        "/api/holder-keys/recover",
        parties.admin().headers(),
        Map.of(
            "recoveryId", recoveryId,
            "newHolderJwk", mapper.convertValue(fresh.jwk(), Map.class),
            "newKeyProof", recoveryProof(fresh, recoveryId),
            "deviceLabel", "Pixel 9"));
    UUID replacement = deviceId(Case.enrollmentId(), "Pixel 9");
    assertThat(deviceStatus(replacement)).isEqualTo("ACTIVE");
    assertThat(keyDevice(Case.enrollmentId())).isEqualTo(replacement);

    // The plan names exactly the report-linked credentials.
    Map<String, Object> plan = get(
        "/api/holder-recoveries/" + recoveryId + "/reissue-plan", parties.ops().headers());
    assertThat(plan.get("enrollmentEligible")).isEqualTo(Boolean.TRUE);
    List<Map<String, Object>> items = (List<Map<String, Object>>) plan.get("items");
    assertThat(items).hasSize(2);
    assertThat(items).allSatisfy(item -> assertThat(item.get("reissuable")).isEqualTo(Boolean.TRUE));

    // Reissuance under fresh holder proofs mints new ids chained to
    // the revoked ones; the revoked ids stay dead.
    Map<String, String> proofs = new LinkedHashMap<>();
    for (Map<String, Object> item : items) {
      proofs.put(
          item.get("credentialId").toString(),
          IssuanceFixtures.proof(
              fresh, item.get("idempotencyKey").toString(), IssuanceFixtures.ADULT_VCT, mapper));
    }
    Map<String, Object> reissued = post(
        "/api/holder-recoveries/" + recoveryId + "/reissue",
        parties.ops().headers(),
        Map.of("proofs", proofs));
    List<Map<String, Object>> credentials =
        (List<Map<String, Object>>) reissued.get("credentials");
    assertThat(credentials).hasSize(2);
    for (Map<String, Object> credential : credentials) {
      assertThat(credentialStatus(credential.get("newCredentialId").toString())).isEqualTo("VALID");
      assertThat(credentialStatus(credential.get("oldCredentialId").toString()))
          .isEqualTo("REVOKED");
      assertThat(supersedes(credential.get("newCredentialId").toString()))
          .isEqualTo(credential.get("oldCredentialId").toString());
    }

    // The replacement credential verifies under the new key...
    String renewed = credentials.get(0).get("newCredentialId").toString();
    String renewedRequest = approvedRequest(parties, renewed, fresh);
    assertThat(present(parties, renewedRequest, fresh).get("outcome")).isEqualTo("ACCEPTED");
    // ...but never under the stolen key.
    assertThat(present(parties, renewedRequest, Case.holder()))
        .containsEntry("outcome", "REJECTED")
        .containsEntry("reasonCode", "HOLDER_MISMATCH");
  }

  @Test
  void reissueBeforeRecoveryIsRefused() throws Exception {
    TestAccount ops = TestAccounts.create(owner, "dev-early", Set.of("ISSUER_OPS"));
    Case Case = approvedCase(ops, FIXTURE);
    issue(ops, Case, Case.holder());
    Map<String, Object> reported = post("/api/holder-keys/report", ops.headers(), Map.of(
        "thumbprint", IssuanceFixtures.thumbprint(Case.holder()), "reason", "loss"));
    String recoveryId = reported.get("recoveryId").toString();
    assertThatThrownBy(() -> get(
            "/api/holder-recoveries/" + recoveryId + "/reissue-plan", ops.headers()))
        .isInstanceOf(HttpClientErrorException.Conflict.class);
    assertThatThrownBy(() -> post(
            "/api/holder-recoveries/" + recoveryId + "/reissue", ops.headers(), Map.of()))
        .isInstanceOf(HttpClientErrorException.Conflict.class);
  }

  @Test
  void expiredCredentialStaysDead() throws Exception {
    Parties parties = Parties.create(owner, "dev-exp");
    Case Case = approvedCase(parties.ops(), FIXTURE);
    String credential = issue(parties.ops(), Case, Case.holder());
    String request = approvedRequest(parties, credential, Case.holder());
    // Consent was valid when given; the credential dies before use.
    owner.update(
        "UPDATE credential_artifact SET expires_at = now() - interval '1 minute' WHERE id = ?",
        UUID.fromString(credential));
    assertThat(present(parties, request, Case.holder()))
        .containsEntry("outcome", "REJECTED")
        .containsEntry("reasonCode", "CREDENTIAL_EXPIRED");
  }

  @Test
  @SuppressWarnings("unchecked")
  void missingProofFailsTheBatchAtomically() throws Exception {
    Parties parties =
        Parties.create(owner, "dev-batch");
    Case Case = approvedCase(parties.ops(), FIXTURE);
    issue(parties.ops(), Case, Case.holder());
    issue(parties.ops(), Case, Case.holder());
    Recovered recovered = recoverCase(parties, Case, "theft");
    Map<String, Object> plan = get(
        "/api/holder-recoveries/" + recovered.recoveryId() + "/reissue-plan",
        parties.ops().headers());
    List<Map<String, Object>> items = (List<Map<String, Object>>) plan.get("items");
    assertThat(items).hasSize(2);
    // One proof short: the whole batch refuses, minting nothing.
    Map<String, String> partial = Map.of(
        items.get(0).get("credentialId").toString(),
        IssuanceFixtures.proof(
            recovered.fresh(),
            items.get(0).get("idempotencyKey").toString(),
            IssuanceFixtures.ADULT_VCT,
            mapper));
    assertThatThrownBy(() -> post(
            "/api/holder-recoveries/" + recovered.recoveryId() + "/reissue",
            parties.ops().headers(),
            Map.of("proofs", partial)))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    assertThat(countValid(Case.enrollmentId())).isEqualTo(0);
    // A proof from the wrong key fails issuance, not silently.
    Map<String, String> wrong = new LinkedHashMap<>();
    for (Map<String, Object> item : items) {
      wrong.put(
          item.get("credentialId").toString(),
          IssuanceFixtures.proof(
              Case.holder(),
              item.get("idempotencyKey").toString(),
              IssuanceFixtures.ADULT_VCT,
              mapper));
    }
    assertThatThrownBy(() -> post(
            "/api/holder-recoveries/" + recovered.recoveryId() + "/reissue",
            parties.ops().headers(),
            Map.of("proofs", wrong)))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    assertThat(countValid(Case.enrollmentId())).isEqualTo(0);
  }

  @Test
  @SuppressWarnings("unchecked")
  void reissueIsIdempotent() throws Exception {
    Parties parties =
        Parties.create(owner, "dev-idem");
    Case Case = approvedCase(parties.ops(), FIXTURE);
    issue(parties.ops(), Case, Case.holder());
    Recovered recovered = recoverCase(parties, Case, "compromise");
    Map<String, Object> plan = get(
        "/api/holder-recoveries/" + recovered.recoveryId() + "/reissue-plan",
        parties.ops().headers());
    List<Map<String, Object>> items = (List<Map<String, Object>>) plan.get("items");
    Map<String, String> proofs = new LinkedHashMap<>();
    for (Map<String, Object> item : items) {
      proofs.put(
          item.get("credentialId").toString(),
          IssuanceFixtures.proof(
              recovered.fresh(),
              item.get("idempotencyKey").toString(),
              IssuanceFixtures.ADULT_VCT,
              mapper));
    }
    Map<String, Object> first = post(
        "/api/holder-recoveries/" + recovered.recoveryId() + "/reissue",
        parties.ops().headers(),
        Map.of("proofs", proofs));
    Map<String, Object> second = post(
        "/api/holder-recoveries/" + recovered.recoveryId() + "/reissue",
        parties.ops().headers(),
        Map.of("proofs", proofs));
    assertThat(second.get("credentials")).isEqualTo(first.get("credentials"));
    assertThat(countValid(Case.enrollmentId())).isEqualTo(1);
  }

  @Test
  void deviceReportNegatives() throws Exception {
    TestAccount ops = TestAccounts.create(owner, "dev-neg", Set.of("ISSUER_OPS"));
    Case Case = approvedCase(ops, FIXTURE);
    UUID primary = deviceId(Case.enrollmentId(), "primary");
    assertThatThrownBy(() -> post(
            "/api/holder-devices/report",
            ops.headers(),
            Map.of("deviceId", UUID.randomUUID().toString(), "reason", "theft")))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
    assertThatThrownBy(() -> post(
            "/api/holder-devices/report", ops.headers(),
            Map.of("deviceId", primary.toString(), "reason", "misplaced")))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    post("/api/holder-devices/report", ops.headers(),
        Map.of("deviceId", primary.toString(), "reason", "loss"));
    assertThatThrownBy(() -> post(
            "/api/holder-devices/report", ops.headers(),
            Map.of("deviceId", primary.toString(), "reason", "theft")))
        .isInstanceOf(HttpClientErrorException.Conflict.class);
  }

  private record Parties(TestAccount ops, TestAccount admin, TestAccount rp, TestAccount agent) {
    static Parties create(JdbcTemplate owner, String tag) {
      TestAccount ops = TestAccounts.create(owner, tag + "-ops", Set.of("ISSUER_OPS"));
      TestAccount admin = TestAccounts.createInTenant(
          owner, ops.tenantId(), tag + "-admin", Set.of("TRUST_ADMIN"));
      TestAccount rp = TestAccounts.createInTenant(
          owner, ops.tenantId(), tag + "-rp", Set.of("RP_CLIENT"));
      TestAccount agent = TestAccounts.createInTenant(
          owner, ops.tenantId(), tag + "-agent", Set.of("TENANT_MEMBER"));
      return new Parties(ops, admin, rp, agent);
    }
  }

  private record Case(String enrollmentId, IssuanceFixtures.HolderKeys holder) {}

  private record Recovered(String recoveryId, IssuanceFixtures.HolderKeys fresh) {}

  private record SourceIds(String objectId, String recordId) {}

  /** Key-level report plus trust-admin recovery onto a fresh device. */
  private Recovered recoverCase(Parties parties, Case Case, String reason) throws Exception {
    Map<String, Object> reported = post("/api/holder-keys/report", parties.ops().headers(), Map.of(
        "thumbprint", IssuanceFixtures.thumbprint(Case.holder()), "reason", reason));
    String recoveryId = reported.get("recoveryId").toString();
    IssuanceFixtures.HolderKeys fresh = IssuanceFixtures.generateHolder(mapper);
    post(
        "/api/holder-keys/recover",
        parties.admin().headers(),
        Map.of(
            "recoveryId", recoveryId,
            "newHolderJwk", mapper.convertValue(fresh.jwk(), Map.class),
            "newKeyProof", recoveryProof(fresh, recoveryId),
            "deviceLabel", "replacement-" + reason));
    return new Recovered(recoveryId, fresh);
  }

  /** Consent request the holder approved: ready for presentation. */
  private String approvedRequest(
      Parties parties, String credentialId, IssuanceFixtures.HolderKeys holder) throws Exception {
    Map<String, Object> created = ConsentFixtures.create(
        client, parties.rp(), ConsentFixtures.createBody(UUID.fromString(credentialId)));
    String requestId = created.get("requestId").toString();
    Map<String, Object> review = ConsentFixtures.review(client, parties.rp(), requestId);
    ConsentFixtures.decide(
        client, parties.agent(), requestId,
        ConsentFixtures.decideBody(holder, review, "approve", mapper));
    return requestId;
  }

  private Map<String, Object> present(
      Parties parties, String requestId, IssuanceFixtures.HolderKeys holder) throws Exception {
    return VerificationFixtures.verify(
        client,
        parties.rp(),
        VerificationFixtures.verifyBody(
            holder, requestId, VerificationFixtures.nonce(), ConsentFixtures.AUDIENCE, mapper));
  }

  private String recoveryProof(IssuanceFixtures.HolderKeys fresh, String recoveryId)
      throws Exception {
    return IssuanceFixtures.proofOver(
        fresh,
        "holder-recovery\n" + recoveryId + "\n" + IssuanceFixtures.thumbprint(fresh),
        mapper);
  }

  private Case approvedCase(TestAccount ops, String text) throws Exception {
    TestAccount checker = TestAccounts.createInTenant(
        owner, ops.tenantId(), "dev-checker-" + UUID.randomUUID().toString().substring(0, 8),
        Set.of("ISSUER_OPS"));
    SourceIds source = recordIdFor(ops, text);
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
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
        "issuerId", "https://issuer.example/device-1",
        "displayName", "device custody source",
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
    String key = "dev-" + UUID.randomUUID();
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

  private UUID deviceId(String enrollmentId, String label) {
    return owner.queryForObject(
        "SELECT id FROM holder_device WHERE enrollment_id = ? AND label = ?",
        UUID.class, UUID.fromString(enrollmentId), label);
  }

  private String deviceStatus(UUID deviceId) {
    return owner.queryForObject(
        "SELECT status FROM holder_device WHERE id = ?", String.class, deviceId);
  }

  private UUID keyDevice(String enrollmentId) {
    return owner.queryForObject(
        "SELECT device_id FROM holder_key WHERE enrollment_id = ? AND status = 'ACTIVE'",
        UUID.class, UUID.fromString(enrollmentId));
  }

  private String credentialStatus(String credentialId) {
    return owner.queryForObject(
        "SELECT status FROM credential_artifact WHERE id = ?", String.class,
        UUID.fromString(credentialId));
  }

  private String supersedes(String credentialId) {
    return owner.queryForObject(
        "SELECT supersedes::text FROM credential_artifact WHERE id = ?", String.class,
        UUID.fromString(credentialId));
  }

  private int countValid(String enrollmentId) {
    // Enrollment linkage is by holder binding: count VALID rows for
    // the enrollment's live key.
    return owner.queryForObject(
        "SELECT COUNT(*) FROM credential_artifact c JOIN holder_key k"
            + " ON k.thumbprint = c.holder_thumbprint AND k.tenant_id = c.tenant_id"
            + " WHERE k.enrollment_id = ? AND c.status = 'VALID'",
        Integer.class, UUID.fromString(enrollmentId));
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
