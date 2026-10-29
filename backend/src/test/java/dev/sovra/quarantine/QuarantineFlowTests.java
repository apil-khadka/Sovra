package dev.sovra.quarantine;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.vault.SoftwareVaultKekProvider;
import dev.sovra.worker.QuarantineWorker;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.HexFormat;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

/**
 * Quarantine happy paths (SOV-017): admit hostile bytes into the
 * sealed queue, scan them through the isolated worker role, promote
 * only CLEAN verdicts into re-sealed vault objects, and prove
 * rejected or unscanned bytes never reach the content endpoint.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class QuarantineFlowTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  @Value("${sovra.vault.seed}")
  String vaultSeed;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
  }

  private QuarantineWorker worker() {
    return new QuarantineWorker(
        quarantineRoleDataSource(), new SoftwareVaultKekProvider(vaultSeed, true));
  }

  private static byte[] fixture(String name) throws Exception {
    try (InputStream in =
        QuarantineFlowTests.class.getResourceAsStream("/quarantine/" + name)) {
      assertThat(in).as("fixture " + name).isNotNull();
      return in.readAllBytes();
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void admitScanPromoteReadRoundTrip() throws Exception {
    TestAccount ops = TestAccounts.create(owner, "quar-ops", Set.of("ISSUER_OPS"));
    byte[] content = fixture("tiny.png");
    String pin = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));

    ResponseEntity<Map> admitted = client.post().uri("/api/quarantine/admissions")
        .headers(ops.headers())
        .body(Map.of(
            "issuerId", "https://issuer.example/quarantine-1",
            "claimedType", "png",
            "contentBase64", Base64.getEncoder().encodeToString(content)))
        .retrieve().toEntity(Map.class);
    assertThat(admitted.getStatusCode().value()).isEqualTo(202);
    Map<String, Object> body = admitted.getBody();
    assertThat(body.get("status")).isEqualTo("QUARANTINED");
    assertThat(body.get("actualType")).isEqualTo("png");
    assertThat(body.get("sizeBytes")).isEqualTo(content.length);
    String admissionId = body.get("admissionId").toString();
    String quarantineObject = body.get("objectId").toString();
    assertThat(body.toString()).doesNotContain("contentBase64", "ciphertext");

    Map<String, Object> fetched = client.get()
        .uri("/api/quarantine/admissions/" + admissionId).headers(ops.headers())
        .retrieve().body(Map.class);
    assertThat(fetched.get("status")).isEqualTo("QUARANTINED");
    assertThat(fetched.get("contentSha256Hex")).isEqualTo(pin);

    drain();

    Map<String, Object> scanned = client.get()
        .uri("/api/quarantine/admissions/" + admissionId).headers(ops.headers())
        .retrieve().body(Map.class);
    assertThat(scanned.get("status")).isEqualTo("CLEAN");
    assertThat(scanned.get("imageWidth")).isEqualTo(8);
    assertThat(scanned.get("imageHeight")).isEqualTo(8);
    assertThat(scanned.get("verdict").toString()).startsWith("clean");
    assertThat(scanned.get("scannedAt")).isNotNull();

    // Promotion opens the quarantine seal server-side under a grant
    // the operator holds, then re-seals into a fresh vault object.
    String scanGrant = grant(ops, quarantineObject, "quarantine-scan", "scan-desk");
    ResponseEntity<Map> promoted = client.post()
        .uri("/api/quarantine/admissions/" + admissionId + "/promote")
        .headers(ops.headers())
        .body(Map.of(
            "grantId", scanGrant,
            "purpose", "quarantine-scan",
            "workload", "scan-desk",
            "purposes", List.of("enrollment-review"),
            "displayName", "promoted doc"))
        .retrieve().toEntity(Map.class);
    assertThat(promoted.getStatusCode().value()).isEqualTo(201);
    Map<String, Object> promotion = promoted.getBody();
    String objectId = promotion.get("objectId").toString();
    assertThat(promotion.get("version")).isEqualTo(1);

    String readGrant = grant(ops, objectId, "enrollment-review", "review-desk");
    Map<String, Object> read = client.post()
        .uri("/api/vault/objects/" + objectId + "/versions/1/read")
        .headers(ops.headers())
        .body(Map.of(
            "grantId", readGrant, "purpose", "enrollment-review", "workload", "review-desk"))
        .retrieve().body(Map.class);
    assertThat(read.get("contentSha256Hex")).isEqualTo(pin);
    assertThat(Base64.getDecoder().decode(read.get("contentBase64").toString()))
        .isEqualTo(content);

    Map<String, Object> done = client.get()
        .uri("/api/quarantine/admissions/" + admissionId).headers(ops.headers())
        .retrieve().body(Map.class);
    assertThat(done.get("status")).isEqualTo("PROMOTED");

    // A second promote conflicts instead of re-sealing.
    assertThatThrownBy(() -> client.post()
            .uri("/api/quarantine/admissions/" + admissionId + "/promote")
            .headers(ops.headers())
            .body(Map.of(
                "grantId", scanGrant,
                "purpose", "quarantine-scan",
                "workload", "scan-desk",
                "purposes", List.of("enrollment-review")))
            .retrieve().toEntity(Map.class))
        .isInstanceOf(HttpClientErrorException.Conflict.class);

    // A promoted admission is not work: the queue is idle afterwards.
    drain();
    assertThat(worker().scanOne()).isFalse();
  }

  @Test
  @SuppressWarnings("unchecked")
  void rejectedBytesNeverPromote() throws Exception {
    TestAccount ops = TestAccounts.create(owner, "quar-rej", Set.of("ISSUER_OPS"));
    String admissionId = admit(ops, "polyglot.png", "png");
    drain();

    Map<String, Object> scanned = client.get()
        .uri("/api/quarantine/admissions/" + admissionId).headers(ops.headers())
        .retrieve().body(Map.class);
    assertThat(scanned.get("status")).isEqualTo("REJECTED");
    assertThat(scanned.get("verdict").toString()).startsWith("trailing-data");

    assertThatThrownBy(() -> client.post()
            .uri("/api/quarantine/admissions/" + admissionId + "/promote")
            .headers(ops.headers())
            .body(Map.of(
                "grantId", UUID.randomUUID().toString(),
                "purpose", "quarantine-scan",
                "workload", "scan-desk",
                "purposes", List.of("enrollment-review")))
            .retrieve().toEntity(Map.class))
        .isInstanceOf(HttpClientErrorException.Conflict.class);

    Map<String, Object> still = client.get()
        .uri("/api/quarantine/admissions/" + admissionId).headers(ops.headers())
        .retrieve().body(Map.class);
    assertThat(still.get("status")).isEqualTo("REJECTED");
  }

  @Test
  void promoteBeforeScanConflicts() throws Exception {
    TestAccount ops = TestAccounts.create(owner, "quar-early", Set.of("ISSUER_OPS"));
    String admissionId = admit(ops, "tiny.jpg", "jpg");
    assertThatThrownBy(() -> client.post()
            .uri("/api/quarantine/admissions/" + admissionId + "/promote")
            .headers(ops.headers())
            .body(Map.of(
                "grantId", UUID.randomUUID().toString(),
                "purpose", "quarantine-scan",
                "workload", "scan-desk",
                "purposes", List.of("enrollment-review")))
            .retrieve().toEntity(Map.class))
        .isInstanceOf(HttpClientErrorException.Conflict.class);
  }

  @Test
  @SuppressWarnings("unchecked")
  void claimedTypeMismatchIsAdmittedButFlagged() throws Exception {
    TestAccount ops = TestAccounts.create(owner, "quar-spoof", Set.of("ISSUER_OPS"));
    // The claim is only a label: admission succeeds, and the worker's
    // independent re-sniff flags the lie on the verdict.
    String admissionId = admit(ops, "tiny.jpg", "png");
    drain();

    Map<String, Object> scanned = client.get()
        .uri("/api/quarantine/admissions/" + admissionId).headers(ops.headers())
        .retrieve().body(Map.class);
    assertThat(scanned.get("status")).isEqualTo("CLEAN");
    assertThat(scanned.get("actualType")).isEqualTo("jpeg");
    assertThat(scanned.get("verdict").toString()).contains("mismatches");
  }

  @Test
  void unknownMagicIsRefused() {
    TestAccount ops = TestAccounts.create(owner, "quar-magic", Set.of("ISSUER_OPS"));
    byte[] content = "not an image".getBytes(StandardCharsets.UTF_8);
    assertThatThrownBy(() -> client.post().uri("/api/quarantine/admissions")
            .headers(ops.headers())
            .body(Map.of(
                "issuerId", "https://issuer.example/quarantine-1",
                "contentBase64", Base64.getEncoder().encodeToString(content)))
            .retrieve().toEntity(Map.class))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void oversizeAdmissionIsRefused() {
    TestAccount ops = TestAccounts.create(owner, "quar-big", Set.of("ISSUER_OPS"));
    byte[] content = new byte[8 * 1024 * 1024 + 1];
    assertThatThrownBy(() -> client.post().uri("/api/quarantine/admissions")
            .headers(ops.headers())
            .body(Map.of(
                "issuerId", "https://issuer.example/quarantine-1",
                "contentBase64", Base64.getEncoder().encodeToString(content)))
            .retrieve().toEntity(Map.class))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void wrongRoleCannotAdmitOrPromote() throws Exception {
    TestAccount member = TestAccounts.create(owner, "quar-member", Set.of("TENANT_MEMBER"));
    byte[] content = fixture("tiny.png");
    assertThatThrownBy(() -> client.post().uri("/api/quarantine/admissions")
            .headers(member.headers())
            .body(Map.of(
                "issuerId", "https://issuer.example/quarantine-1",
                "contentBase64", Base64.getEncoder().encodeToString(content)))
            .retrieve().toEntity(Map.class))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(() -> client.post()
            .uri("/api/quarantine/admissions/" + UUID.randomUUID() + "/promote")
            .headers(member.headers())
            .body(Map.of(
                "grantId", UUID.randomUUID().toString(),
                "purpose", "quarantine-scan",
                "workload", "scan-desk"))
            .retrieve().toEntity(Map.class))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
  }

  @Test
  @SuppressWarnings("unchecked")
  void auditorReadsVerdictsNeverBytes() throws Exception {
    TestAccount ops = TestAccounts.create(owner, "quar-aud-ops", Set.of("ISSUER_OPS"));
    TestAccount auditor = TestAccounts.createInTenant(
        owner, ops.tenantId(), "quar-auditor", Set.of("AUDIT_READER"));
    String admissionId = admit(ops, "tiny.png", "png");
    drain();

    Map<String, Object> verdict = client.get()
        .uri("/api/quarantine/admissions/" + admissionId).headers(auditor.headers())
        .retrieve().body(Map.class);
    assertThat(verdict.get("status")).isEqualTo("CLEAN");
    assertThat(verdict.toString()).doesNotContain("contentBase64", "ciphertext");

    assertThatThrownBy(() -> client.post()
            .uri("/api/quarantine/admissions/" + admissionId + "/promote")
            .headers(auditor.headers())
            .body(Map.of(
                "grantId", UUID.randomUUID().toString(),
                "purpose", "quarantine-scan",
                "workload", "scan-desk"))
            .retrieve().toEntity(Map.class))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
  }

  @Test
  @SuppressWarnings("unchecked")
  void quarantinedBytesNeverLeaveThroughContentEndpoint() throws Exception {
    TestAccount ops = TestAccounts.create(owner, "quar-gate", Set.of("ISSUER_OPS"));
    String admissionId = admit(ops, "tiny.png", "png");
    Map<String, Object> fetched = client.get()
        .uri("/api/quarantine/admissions/" + admissionId).headers(ops.headers())
        .retrieve().body(Map.class);
    String objectId = fetched.get("objectId").toString();
    // Even scanned-clean, the quarantine-marked seal is not content:
    // promotion re-seals it instead.
    drain();

    String scanGrant = grant(ops, objectId, "quarantine-scan", "scan-desk");
    assertThatThrownBy(() -> client.post()
            .uri("/api/vault/objects/" + objectId + "/versions/1/read")
            .headers(ops.headers())
            .body(Map.of(
                "grantId", scanGrant, "purpose", "quarantine-scan", "workload", "scan-desk"))
            .retrieve().toEntity(Map.class))
        .isInstanceOf(HttpClientErrorException.Forbidden.class)
        .hasMessageContaining("GRANT_INVALID");
  }

  @SuppressWarnings("unchecked")
  private String admit(TestAccount ops, String file, String claimedType) throws Exception {
    byte[] content = fixture(file);
    Map<String, Object> admitted = client.post().uri("/api/quarantine/admissions")
        .headers(ops.headers())
        .body(Map.of(
            "issuerId", "https://issuer.example/quarantine-1",
            "claimedType", claimedType,
            "contentBase64", Base64.getEncoder().encodeToString(content)))
        .retrieve().body(Map.class);
    assertThat(admitted.get("status")).isEqualTo("QUARANTINED");
    return admitted.get("admissionId").toString();
  }

  @SuppressWarnings("unchecked")
  private String grant(TestAccount ops, String objectId, String purpose, String workload) {
    Map<String, Object> granted = client.post().uri("/api/vault/grants")
        .headers(ops.headers())
        .body(Map.of(
            "objectId", objectId, "objectVersion", 1,
            "purpose", purpose, "workload", workload, "ttlSeconds", 3600))
        .retrieve().body(Map.class);
    return granted.get("grantId").toString();
  }

  // Admissions share one queue across tests; draining keeps every
  // test independent of execution order.
  private void drain() throws Exception {
    while (worker().scanOne()) {
    }
  }

}
