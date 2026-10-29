package dev.sovra.demo;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
}
