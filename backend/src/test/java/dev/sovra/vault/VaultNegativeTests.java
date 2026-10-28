package dev.sovra.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.audit.AuditService;
import dev.sovra.auth.HumanMembershipRepository;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.auth.ServiceAccountRepository;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.issuance.KmsUnavailableException;
import dev.sovra.tenancy.TenantContext;
import dev.sovra.tenancy.TenantDataSource;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClient;

/**
 * Vault adversarial matrix (SOV-016, SEC-33/34/35, INV-10/11): grant
 * confusion, tamper fail-closed, role exclusion, tenant isolation,
 * and outage behavior.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class VaultNegativeTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  @Autowired DataSource dataSource;

  @Autowired AuthorizationService authz;

  @Autowired AuditService audit;

  @Autowired ServiceAccountRepository accounts;

  @Autowired HumanMembershipRepository humans;

  @Autowired Clock clock;

  @Autowired org.springframework.transaction.PlatformTransactionManager transactions;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
  }

  @Test
  void anonymousReadsDenied() {
    assertThatThrownBy(() -> client.post()
            .uri("/api/vault/objects/" + UUID.randomUUID() + "/versions/1/read")
            .body(Map.of(
                "grantId", UUID.randomUUID().toString(), "purpose", "p", "workload", "w"))
            .retrieve()
            .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
  }

  @Test
  void relyingPartiesNeverSeeSource() {
    TestAccount issuer = TestAccounts.create(owner, "vn-issuer", Set.of("ISSUER_OPS"));
    String objectId = store(issuer, "rp-bytes");
    TestAccount rp = TestAccounts.createInTenant(
        owner, issuer.tenantId(), "vn-rp", Set.of("RP_CLIENT"));
    Map<String, Object> granted = post("/api/vault/grants", issuer.headers(), Map.of(
        "objectId", objectId, "objectVersion", 1, "principalType", "service_account",
        "principalId", rp.accountId().toString(), "purpose", "enrollment-review",
        "workload", "review-desk", "ttlSeconds", 3600));
    // Even holding a live grant, the relying party fails the role gate.
    assertThatThrownBy(() -> post(
            "/api/vault/objects/" + objectId + "/versions/1/read", rp.headers(), Map.of(
                "grantId", granted.get("grantId").toString(),
                "purpose", "enrollment-review", "workload", "review-desk")))
        .isInstanceOf(HttpClientErrorException.Forbidden.class)
        .hasMessageContaining("MISSING_ROLE");
  }

  @Test
  void auditorsSeeMetadataNeverContent() {
    TestAccount issuer = TestAccounts.create(owner, "vn-aud-issuer", Set.of("ISSUER_OPS"));
    String objectId = store(issuer, "aud-bytes");
    TestAccount auditor = TestAccounts.createInTenant(
        owner, issuer.tenantId(), "vn-auditor", Set.of("AUDIT_READER"));
    Map<String, Object> meta = client.get().uri("/api/vault/objects/" + objectId)
        .headers(auditor.headers()).retrieve().body(Map.class);
    assertThat(meta.get("objectId")).isEqualTo(objectId);
    Map<String, Object> granted = post("/api/vault/grants", issuer.headers(), Map.of(
        "objectId", objectId, "objectVersion", 1, "principalType", "service_account",
        "principalId", auditor.accountId().toString(), "purpose", "enrollment-review",
        "workload", "review-desk", "ttlSeconds", 3600));
    assertThatThrownBy(() -> post(
            "/api/vault/objects/" + objectId + "/versions/1/read", auditor.headers(),
            Map.of(
                "grantId", granted.get("grantId").toString(),
                "purpose", "enrollment-review", "workload", "review-desk")))
        .isInstanceOf(HttpClientErrorException.Forbidden.class)
        .hasMessageContaining("MISSING_ROLE");
  }

  @Test
  void membersCannotSeal() {
    TestAccount member = TestAccounts.create(owner, "vn-member", Set.of("TENANT_MEMBER"));
    assertThatThrownBy(() -> post("/api/vault/objects", member.headers(), Map.of(
            "issuerId", "https://issuer.example/x",
            "purposes", List.of("enrollment-review"),
            "contentBase64", base64("nope"))))
        .isInstanceOf(HttpClientErrorException.Forbidden.class)
        .hasMessageContaining("MISSING_ROLE");
  }

  @Test
  void wrongPurposeDenied() {
    GrantFixture fixture = granted("vn-purpose");
    assertThatThrownBy(() -> post(
            "/api/vault/objects/" + fixture.objectId() + "/versions/1/read",
            fixture.reader().headers(), Map.of(
                "grantId", fixture.grantId(), "purpose", "verification-display",
                "workload", "review-desk")))
        .isInstanceOf(HttpClientErrorException.Forbidden.class)
        .hasMessageContaining("GRANT_INVALID");
  }

  @Test
  void wrongWorkloadDenied() {
    GrantFixture fixture = granted("vn-workload");
    assertThatThrownBy(() -> post(
            "/api/vault/objects/" + fixture.objectId() + "/versions/1/read",
            fixture.reader().headers(), Map.of(
                "grantId", fixture.grantId(), "purpose", "enrollment-review",
                "workload", "other-desk")))
        .isInstanceOf(HttpClientErrorException.Forbidden.class)
        .hasMessageContaining("GRANT_INVALID");
  }

  @Test
  void foreignGrantDenied() {
    GrantFixture fixture = granted("vn-foreign");
    TestAccount stranger = TestAccounts.createInTenant(
        owner, fixture.tenantId(), "vn-stranger", Set.of("TENANT_MEMBER"));
    assertThatThrownBy(() -> post(
            "/api/vault/objects/" + fixture.objectId() + "/versions/1/read",
            stranger.headers(), Map.of(
                "grantId", fixture.grantId(), "purpose", "enrollment-review",
                "workload", "review-desk")))
        .isInstanceOf(HttpClientErrorException.Forbidden.class)
        .hasMessageContaining("GRANT_INVALID");
  }

  @Test
  void expiredGrantDenied() {
    GrantFixture fixture = granted("vn-expired");
    // Age the grant honestly: both timestamps move, so the
    // expires-after-created row invariant still holds.
    owner.update(
        "UPDATE vault_grant SET created_at = now() - INTERVAL '2 hours',"
            + " expires_at = now() - INTERVAL '1 hour' WHERE id = ?",
        UUID.fromString(fixture.grantId()));
    assertThatThrownBy(() -> post(
            "/api/vault/objects/" + fixture.objectId() + "/versions/1/read",
            fixture.reader().headers(), Map.of(
                "grantId", fixture.grantId(), "purpose", "enrollment-review",
                "workload", "review-desk")))
        .isInstanceOf(HttpClientErrorException.Forbidden.class)
        .hasMessageContaining("GRANT_EXPIRED");
  }

  @Test
  void widenedPurposeGrantRefused() {
    TestAccount issuer = TestAccounts.create(owner, "vn-widen", Set.of("ISSUER_OPS"));
    String objectId = store(issuer, "widen-bytes");
    assertThatThrownBy(() -> post("/api/vault/grants", issuer.headers(), Map.of(
            "objectId", objectId, "objectVersion", 1, "purpose", "unlisted-purpose",
            "workload", "review-desk", "ttlSeconds", 3600)))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void crossTenantReadsEmpty() {
    TestAccount issuer = TestAccounts.create(owner, "vn-tenant", Set.of("ISSUER_OPS"));
    String objectId = store(issuer, "tenant-bytes");
    Map<String, Object> granted = post("/api/vault/grants", issuer.headers(), Map.of(
        "objectId", objectId, "objectVersion", 1, "purpose", "enrollment-review",
        "workload", "review-desk", "ttlSeconds", 3600));
    TestAccount outsider = TestAccounts.create(owner, "vn-outsider", Set.of("ISSUER_OPS"));
    assertThatThrownBy(() -> client.get().uri("/api/vault/objects/" + objectId)
            .headers(outsider.headers()).retrieve().toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.NotFound.class);
    assertThatThrownBy(() -> post(
            "/api/vault/objects/" + objectId + "/versions/1/read", outsider.headers(),
            Map.of(
                "grantId", granted.get("grantId").toString(),
                "purpose", "enrollment-review", "workload", "review-desk")))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
  }

  @Test
  void tamperedCiphertextFailsClosedWithoutPlaintext() {
    GrantFixture fixture = granted("vn-tamper");
    byte[] raw = owner.queryForObject(
        "SELECT ciphertext FROM vault_object_version WHERE object_id = ? AND version = 1",
        byte[].class, UUID.fromString(fixture.objectId()));
    assertThat(raw).isNotNull();
    raw[raw.length / 2] ^= 0x01;
    owner.update(
        "UPDATE vault_object_version SET ciphertext = ? WHERE object_id = ? AND version = 1",
        raw, UUID.fromString(fixture.objectId()));
    assertThatThrownBy(() -> post(
            "/api/vault/objects/" + fixture.objectId() + "/versions/1/read",
            fixture.reader().headers(), Map.of(
                "grantId", fixture.grantId(), "purpose", "enrollment-review",
                "workload", "review-desk")))
        .isInstanceOf(HttpServerErrorException.InternalServerError.class)
        .hasMessageContaining("vault_integrity_failure")
        .hasMessageNotContaining("tamper-bytes");
    Map<String, Object> denial = owner.queryForMap(
        "SELECT decision, reason_code FROM audit_event WHERE tenant_id = ?"
            + " AND action = 'VAULT_READ_OBJECT' ORDER BY occurred_at DESC LIMIT 1",
        fixture.tenantId());
    assertThat(denial.get("decision")).isEqualTo("DENY");
    assertThat(denial.get("reason_code")).isEqualTo("VAULT_INTEGRITY_FAILURE");
  }

  @Test
  void substitutedPurposesFailClosed() {
    GrantFixture fixture = granted("vn-subst");
    // The attacker widens the row's purpose set; the wrap AAD was
    // computed over the original set, so the unwrap refuses.
    owner.update(
        "UPDATE vault_object_version SET authorized_purposes"
            + " = array_append(authorized_purposes, 'smuggled-purpose')"
            + " WHERE object_id = ? AND version = 1",
        UUID.fromString(fixture.objectId()));
    assertThatThrownBy(() -> post(
            "/api/vault/objects/" + fixture.objectId() + "/versions/1/read",
            fixture.reader().headers(), Map.of(
                "grantId", fixture.grantId(), "purpose", "enrollment-review",
                "workload", "review-desk")))
        .isInstanceOf(HttpServerErrorException.InternalServerError.class)
        .hasMessageContaining("vault_integrity_failure");
  }

  @Test
  void substitutedWrappedDekFailsClosed() {
    GrantFixture fixture = granted("vn-wrap");
    byte[] wrapped = owner.queryForObject(
        "SELECT wrapped_dek FROM vault_object_version WHERE object_id = ? AND version = 1",
        byte[].class, UUID.fromString(fixture.objectId()));
    assertThat(wrapped).isNotNull();
    wrapped[0] ^= 0x01;
    owner.update(
        "UPDATE vault_object_version SET wrapped_dek = ? WHERE object_id = ? AND version = 1",
        wrapped, UUID.fromString(fixture.objectId()));
    assertThatThrownBy(() -> post(
            "/api/vault/objects/" + fixture.objectId() + "/versions/1/read",
            fixture.reader().headers(), Map.of(
                "grantId", fixture.grantId(), "purpose", "enrollment-review",
                "workload", "review-desk")))
        .isInstanceOf(HttpServerErrorException.InternalServerError.class)
        .hasMessageContaining("vault_integrity_failure");
  }

  @Test
  void digestMismatchRefused() {
    TestAccount issuer = TestAccounts.create(owner, "vn-digest", Set.of("ISSUER_OPS"));
    assertThatThrownBy(() -> post("/api/vault/objects", issuer.headers(), Map.of(
            "issuerId", "https://issuer.example/x",
            "purposes", List.of("enrollment-review"),
            "contentBase64", base64("digest-bytes"),
            "contentSha256Hex", "0".repeat(64))))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void grantBoundsEnforced() {
    TestAccount issuer = TestAccounts.create(owner, "vn-bounds", Set.of("ISSUER_OPS"));
    String objectId = store(issuer, "bounds-bytes");
    for (long ttl : new long[] {59, 86401}) {
      assertThatThrownBy(() -> post("/api/vault/grants", issuer.headers(), Map.of(
              "objectId", objectId, "objectVersion", 1, "purpose", "enrollment-review",
              "workload", "review-desk", "ttlSeconds", ttl)))
          .as("ttl %d must refuse", ttl)
          .isInstanceOf(HttpClientErrorException.BadRequest.class);
    }
    assertThatThrownBy(() -> post("/api/vault/grants", issuer.headers(), Map.of(
            "objectId", objectId, "objectVersion", 1, "principalType", "service_account",
            "principalId", UUID.randomUUID().toString(), "purpose", "enrollment-review",
            "workload", "review-desk", "ttlSeconds", 3600)))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
  }

  @Test
  void unknownRoutesEmpty() {
    TestAccount issuer = TestAccounts.create(owner, "vn-404", Set.of("ISSUER_OPS", "TRUST_ADMIN"));
    UUID missing = UUID.randomUUID();
    assertThatThrownBy(() -> client.get().uri("/api/vault/objects/" + missing)
            .headers(issuer.headers()).retrieve().toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.NotFound.class);
    assertThatThrownBy(() -> post(
            "/api/vault/objects/" + missing + "/versions/1/delete", issuer.headers(), Map.of()))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
    assertThatThrownBy(
            () -> post("/api/vault/grants/" + missing + "/revoke", issuer.headers(), Map.of()))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
  }

  @Test
  void wrappingOutageFailsClosedWithNothingSealed() {
    TestAccount issuer = TestAccounts.create(owner, "vn-outage", Set.of("ISSUER_OPS"));
    ServiceAccountPrincipal caller = new ServiceAccountPrincipal(
        issuer.accountId(), issuer.tenantId(), issuer.name(), issuer.roles());
    VaultService failing = new VaultService(authz, audit, accounts, humans,
        new KmsVaultKekProvider(), new JdbcTemplate(new TenantDataSource(dataSource)), clock);
    // The manual instance has no transaction proxy, so the test wraps
    // the call the way the runtime does: the failed seal must roll
    // the object shell back with it.
    assertThatThrownBy(() -> new org.springframework.transaction.support.TransactionTemplate(
            transactions)
        .execute(ignored -> {
          TenantContext.set(caller);
          try {
            assertThatThrownBy(() -> failing.store(caller, "https://issuer.example/x", "",
                    List.of("enrollment-review"),
                    "outage-bytes".getBytes(StandardCharsets.UTF_8), null))
                .isInstanceOf(KmsUnavailableException.class);
          } finally {
            TenantContext.clear();
          }
          throw new RollbackProbe();
        }))
        .isInstanceOf(RollbackProbe.class);
    assertThat(owner.queryForObject(
            "SELECT COUNT(*) FROM vault_object WHERE tenant_id = ?", Integer.class,
            issuer.tenantId()))
        .isZero();
  }

  /** Forces rollback after the outage assertion runs inside a transaction. */
  private static class RollbackProbe extends RuntimeException {}

  private record GrantFixture(
      String objectId, String grantId, TestAccount reader, UUID tenantId) {}

  private GrantFixture granted(String tag) {
    TestAccount issuer = TestAccounts.create(owner, tag + "-issuer", Set.of("ISSUER_OPS"));
    TestAccount reader = TestAccounts.createInTenant(
        owner, issuer.tenantId(), tag + "-reader", Set.of("TENANT_MEMBER"));
    String objectId = store(issuer, tag + "-bytes");
    Map<String, Object> granted = post("/api/vault/grants", issuer.headers(), Map.of(
        "objectId", objectId, "objectVersion", 1, "principalType", "service_account",
        "principalId", reader.accountId().toString(), "purpose", "enrollment-review",
        "workload", "review-desk", "ttlSeconds", 3600));
    return new GrantFixture(
        objectId, granted.get("grantId").toString(), reader, issuer.tenantId());
  }

  private String store(TestAccount issuer, String content) {
    Map<String, Object> stored = post("/api/vault/objects", issuer.headers(), Map.of(
        "issuerId", "https://issuer.example/vault-1",
        "purposes", List.of("enrollment-review", "verification-display"),
        "contentBase64", base64(content)));
    return stored.get("objectId").toString();
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> post(String uri, Consumer<HttpHeaders> headers,
      Map<String, Object> body) {
    return client.post().uri(uri).headers(headers).body(body).retrieve().body(Map.class);
  }

  private static String base64(String text) {
    return Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8));
  }
}
