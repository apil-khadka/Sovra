package dev.sovra.demo;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.config.DemoProperties;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.quarantine.QuarantineService;
import dev.sovra.tenancy.TenantContext;
import dev.sovra.vault.SoftwareVaultKekProvider;
import dev.sovra.vault.VaultService;
import dev.sovra.worker.QuarantineWorker;
import java.io.InputStream;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

/**
 * Public-demo admission boundary (SOV-027): with
 * {@code sovra.demo.synthetic-only=true}, authenticated vault and
 * quarantine ingestion endpoints reject caller-supplied bytes —
 * even valid-looking image bytes from privileged callers — while
 * anonymous callers keep their 401 and metadata reads stay on
 * their normal gates.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = "sovra.demo.synthetic-only=true")
class DemoAdmissionTests extends SovraAppRoleBase {

  /** PNG magic plus filler: passes a sniff, must still be rejected. */
  private static final byte[] VALID_LOOKING_PNG = {
    (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
    0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x02, 0x00, 0x00, 0x00, (byte) 0x90, 0x77, 0x53, (byte) 0xDE
  };

  @LocalServerPort int port;

  @Value("${sovra.vault.seed}")
  String vaultSeed;

  @Autowired DemoProperties demo;
  @Autowired VaultService vault;
  @Autowired QuarantineService quarantine;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
  }

  @Test
  void vaultStoreBlockedForPrivilegedCaller() {
    TestAccount issuer = TestAccounts.create(owner, "demo-issuer", Set.of("ISSUER_OPS"));
    assertThatThrownBy(() -> client.post().uri("/api/vault/objects")
            .headers(issuer.headers())
            .body(Map.of(
                "issuerId", "https://issuer.example/demo-1",
                "purposes", List.of("enrollment-review"),
                "contentBase64",
                    Base64.getEncoder().encodeToString(VALID_LOOKING_PNG)))
            .retrieve()
            .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Forbidden.class)
        .hasMessageContaining("DEMO_SYNTHETIC_ONLY");
  }

  @Test
  void vaultStoreVersionBlockedForPrivilegedCaller() {
    TestAccount issuer = TestAccounts.create(owner, "demo-issuer-v", Set.of("ISSUER_OPS"));
    // Guard runs before the object lookup: even a missing object
    // answers 403, never 404, under synthetic-only.
    assertThatThrownBy(() -> client.post()
            .uri("/api/vault/objects/" + UUID.randomUUID() + "/versions")
            .headers(issuer.headers())
            .body(Map.of(
                "purposes", List.of("enrollment-review"),
                "contentBase64",
                    Base64.getEncoder().encodeToString(VALID_LOOKING_PNG)))
            .retrieve()
            .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Forbidden.class)
        .hasMessageContaining("DEMO_SYNTHETIC_ONLY");
  }

  @Test
  void quarantineAdmitBlockedForPrivilegedCaller() {
    TestAccount issuer = TestAccounts.create(owner, "demo-issuer-q", Set.of("ISSUER_OPS"));
    assertThatThrownBy(() -> client.post().uri("/api/quarantine/admissions")
            .headers(issuer.headers())
            .body(Map.of(
                "contentBase64",
                    Base64.getEncoder().encodeToString(VALID_LOOKING_PNG),
                "claimedType", "png",
                "issuerId", "https://issuer.example/demo-1"))
            .retrieve()
            .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Forbidden.class)
        .hasMessageContaining("DEMO_SYNTHETIC_ONLY");
  }

  @Test
  void anonymousCallersKeepTheirUnauthorized() {
    assertThatThrownBy(() -> client.post().uri("/api/vault/objects")
            .body(Map.of(
                "issuerId", "https://issuer.example/demo-1",
                "purposes", List.of("enrollment-review"),
                "contentBase64",
                    Base64.getEncoder().encodeToString(VALID_LOOKING_PNG)))
            .retrieve()
            .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
  }

  @Test
  void metadataReadsStayOnTheirNormalGate() {
    TestAccount auditor =
        TestAccounts.create(owner, "demo-auditor", Set.of("AUDIT_READER"));
    // Unknown objects still answer 404: the demo boundary blocks
    // ingestion only, it does not swallow reads.
    assertThatThrownBy(() -> client.get()
            .uri("/api/vault/objects/" + UUID.randomUUID())
            .headers(auditor.headers())
            .retrieve()
            .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.NotFound.class);
  }

  @Test
  void quarantineReadsStayOnTheirNormalGate() {
    TestAccount issuer = TestAccounts.create(owner, "demo-issuer-r", Set.of("ISSUER_OPS"));
    assertThatThrownBy(() -> client.get()
            .uri("/api/quarantine/admissions/" + UUID.randomUUID())
            .headers(issuer.headers())
            .retrieve()
            .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.NotFound.class);
  }

  @Test
  @SuppressWarnings("unchecked")
  void promotionStillWorksUnderFlag() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "demo-issuer-p", Set.of("ISSUER_OPS"));
    byte[] content;
    try (InputStream in = DemoAdmissionTests.class.getResourceAsStream("/quarantine/tiny.png")) {
      assertThat(in).isNotNull();
      content = in.readAllBytes();
    }
    // Admit and scan while disarmed (data admitted before the flag
    // was armed); the flag is always restored, even on failure.
    demo.setSyntheticOnly(false);
    String admissionId;
    String quarantineObject;
    try {
      Map<String, Object> admitted = client.post().uri("/api/quarantine/admissions")
          .headers(issuer.headers())
          .body(Map.of(
              "contentBase64", Base64.getEncoder().encodeToString(content),
              "claimedType", "png",
              "issuerId", "https://issuer.example/demo-1"))
          .retrieve()
          .body(Map.class);
      admissionId = admitted.get("admissionId").toString();
      quarantineObject = admitted.get("objectId").toString();
      QuarantineWorker worker = new QuarantineWorker(
          quarantineRoleDataSource(), new SoftwareVaultKekProvider(vaultSeed, true));
      while (worker.scanOne()) {
      }
      Map<String, Object> scanned = client.get()
          .uri("/api/quarantine/admissions/" + admissionId)
          .headers(issuer.headers())
          .retrieve()
          .body(Map.class);
      assertThat(scanned.get("status")).isEqualTo("CLEAN");
    } finally {
      demo.setSyntheticOnly(true);
    }
    // Flag re-armed: the server-side promotion re-seal still works.
    Map<String, Object> granted = client.post().uri("/api/vault/grants")
        .headers(issuer.headers())
        .body(Map.of(
            "objectId", quarantineObject, "objectVersion", 1,
            "purpose", "quarantine-scan", "workload", "scan-desk", "ttlSeconds", 3600))
        .retrieve()
        .body(Map.class);
    org.springframework.http.ResponseEntity<Map> promoted = client.post()
        .uri("/api/quarantine/admissions/" + admissionId + "/promote")
        .headers(issuer.headers())
        .body(Map.of(
            "grantId", granted.get("grantId").toString(),
            "purpose", "quarantine-scan",
            "workload", "scan-desk",
            "purposes", List.of("enrollment-review")))
        .retrieve()
        .toEntity(Map.class);
    assertThat(promoted.getStatusCode().value()).isEqualTo(201);
    // And the boundary is back in force afterwards.
    assertThatThrownBy(() -> client.post().uri("/api/vault/objects")
            .headers(issuer.headers())
            .body(Map.of(
                "issuerId", "https://issuer.example/demo-1",
                "purposes", List.of("enrollment-review"),
                "contentBase64",
                    Base64.getEncoder().encodeToString(VALID_LOOKING_PNG)))
            .retrieve()
            .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Forbidden.class)
        .hasMessageContaining("DEMO_SYNTHETIC_ONLY");
  }

  @Test
  void storeEnforcedAtServiceLayer() {
    TestAccount issuer = TestAccounts.create(owner, "demo-issuer-s", Set.of("ISSUER_OPS"));
    ServiceAccountPrincipal caller = IssuanceFixtures.asPrincipal(issuer);
    TenantContext.set(caller);
    try {
      // Direct service call, no controller involved: the boundary
      // holds, so future caller paths are fail-closed by default.
      assertThatThrownBy(() -> vault.store(
              caller, "https://issuer.example/demo-1", "", List.of("enrollment-review"),
              VALID_LOOKING_PNG, null, VaultService.IngestionSource.CALLER))
          .isInstanceOf(ForbiddenException.class)
          .hasMessageContaining("DEMO_SYNTHETIC_ONLY");
    } finally {
      TenantContext.clear();
    }
  }

  @Test
  void admitEnforcedAtServiceLayer() {
    TestAccount issuer = TestAccounts.create(owner, "demo-issuer-a", Set.of("ISSUER_OPS"));
    ServiceAccountPrincipal caller = IssuanceFixtures.asPrincipal(issuer);
    TenantContext.set(caller);
    try {
      assertThatThrownBy(() -> quarantine.admit(
              caller, VALID_LOOKING_PNG, "png", "https://issuer.example/demo-1"))
          .isInstanceOf(ForbiddenException.class)
          .hasMessageContaining("DEMO_SYNTHETIC_ONLY");
    } finally {
      TenantContext.clear();
    }
  }
}
