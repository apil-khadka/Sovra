package dev.sovra.retention;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

/**
 * Legal hold and audit archival (PROD-010): holds suspend vault
 * destruction and audit archival for the tenant while protocol
 * purges continue; evidence past 90 days moves to the archive in
 * bounded batches, and reads union both tables so archival never
 * hides evidence.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class LegalHoldArchiveTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  RestClient client;
  JdbcTemplate owner;
  JdbcTemplate app;

  static javax.sql.DataSource appPool;

  static synchronized javax.sql.DataSource appRole() {
    if (appPool == null) {
      com.zaxxer.hikari.HikariConfig config = new com.zaxxer.hikari.HikariConfig();
      config.setJdbcUrl(containerJdbcUrl());
      config.setUsername(appRoleName());
      config.setPassword(appRolePassword());
      config.setMaximumPoolSize(2);
      config.setMaxLifetime(300_000);
      appPool = new com.zaxxer.hikari.HikariDataSource(config);
    }
    return appPool;
  }

  @BeforeEach
  void setup() {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
    app = new JdbcTemplate(appRole());
  }

  @Test
  void holdSuspendsVaultDestruction() {
    TestAccount admin =
        TestAccounts.create(owner, "hold-vault", Set.of("ISSUER_OPS", "TRUST_ADMIN"));
    String objectId = store(admin, "held-bytes");
    setHold(admin, admin.tenantId(), true);
    // Delete and purge both refuse while the hold stands.
    assertThatThrownBy(() -> post(
            "/api/vault/objects/" + objectId + "/versions/1/delete", admin.headers(), Map.of()))
        .isInstanceOf(HttpClientErrorException.Conflict.class)
        .hasMessageContaining("legal_hold");
    assertThat(versionStatus(objectId)).isEqualTo("VALID");
    // Release restores the lifecycle.
    setHold(admin, admin.tenantId(), false);
    Map<String, Object> deleted = post(
        "/api/vault/objects/" + objectId + "/versions/1/delete", admin.headers(), Map.of());
    assertThat(deleted.get("status")).isEqualTo("DELETED");
  }

  @Test
  void holdBlocksPurgeEvenAfterTombstone() {
    TestAccount admin =
        TestAccounts.create(owner, "hold-purge", Set.of("ISSUER_OPS", "TRUST_ADMIN"));
    String objectId = store(admin, "purge-bytes");
    post("/api/vault/objects/" + objectId + "/versions/1/delete", admin.headers(), Map.of());
    setHold(admin, admin.tenantId(), true);
    assertThatThrownBy(() -> post(
            "/api/vault/objects/" + objectId + "/versions/1/purge", admin.headers(), Map.of()))
        .isInstanceOf(HttpClientErrorException.Conflict.class)
        .hasMessageContaining("legal_hold");
    assertThat(versionStatus(objectId)).isEqualTo("DELETED");
    // The function backstop refuses direct EXECUTE too: zero rows,
    // never an exception-shaped bypass.
    Integer purged = app.queryForObject(
        "SELECT purge_vault_version(?, 1)", Integer.class, UUID.fromString(objectId));
    assertThat(purged).isEqualTo(0);
    assertThat(versionStatus(objectId)).isEqualTo("DELETED");
    setHold(admin, admin.tenantId(), false);
    post("/api/vault/objects/" + objectId + "/versions/1/purge", admin.headers(), Map.of());
    assertThat(versionStatus(objectId)).isEqualTo("PURGED");
  }

  @Test
  @SuppressWarnings("unchecked")
  void archiveMovesOldRowsAndReadsUnionBoth() {
    TestAccount admin =
        TestAccounts.create(owner, "hold-arch", Set.of("ISSUER_OPS", "TRUST_ADMIN"));
    UUID tenant = admin.tenantId();
    UUID oldEvent = seedAudit(tenant, Instant.now().minusSeconds(91L * 24 * 3600), "ARCHIVE_ME");
    UUID newEvent = seedAudit(tenant, Instant.now(), "STAY_HOT");
    // Held tenants' rows stay hot.
    TestAccount held =
        TestAccounts.create(owner, "hold-arch-held", Set.of("ISSUER_OPS", "TRUST_ADMIN"));
    UUID heldEvent =
        seedAudit(held.tenantId(), Instant.now().minusSeconds(91L * 24 * 3600), "HELD_ROW");
    setHold(held, held.tenantId(), true);
    // Platform rows archive by age; no hold can cover them.
    UUID platformEvent = seedAudit(null, Instant.now().minusSeconds(91L * 24 * 3600), "PLATFORM");

    Integer moved = app.queryForObject("SELECT archive_audit_events(1000)", Integer.class);
    assertThat(moved).isEqualTo(2);
    assertThat(eventTable(oldEvent)).isEqualTo("audit_event_archive");
    assertThat(eventTable(platformEvent)).isEqualTo("audit_event_archive");
    assertThat(eventTable(newEvent)).isEqualTo("audit_event");
    assertThat(eventTable(heldEvent)).isEqualTo("audit_event");

    // Reads union both tables: the archived row is still listed.
    List<Map<String, Object>> events = (List<Map<String, Object>>) (List<?>)
        client.get().uri("/api/audit/events?limit=100").headers(admin.headers())
            .retrieve().body(List.class);
    assertThat(events.stream().map(e -> e.get("id").toString()))
        .contains(oldEvent.toString(), newEvent.toString());
    // Release the hold and the backlog drains next run.
    setHold(held, held.tenantId(), false);
    assertThat(app.queryForObject("SELECT archive_audit_events(1000)", Integer.class))
        .isEqualTo(1);
    assertThat(eventTable(heldEvent)).isEqualTo("audit_event_archive");
  }

  @Test
  @SuppressWarnings("unchecked")
  void holdRolesAndUnknownTenant() {
    TestAccount ops = TestAccounts.create(owner, "hold-ops", Set.of("ISSUER_OPS"));
    TestAccount reader = TestAccounts.createInTenant(
        owner, ops.tenantId(), "hold-reader", Set.of("AUDIT_READER"));
    TestAccount member = TestAccounts.createInTenant(
        owner, ops.tenantId(), "hold-member", Set.of("TENANT_MEMBER"));
    assertThatThrownBy(() -> putHold(ops, ops.tenantId(), true))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(() -> client.get().uri("/api/tenants/holds").headers(member.headers())
            .retrieve().body(Map.class))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    Map<String, Object> register = client.get().uri("/api/tenants/holds")
        .headers(reader.headers()).retrieve().body(Map.class);
    assertThat((List<Map<String, Object>>) register.get("holds"))
        .extracting(row -> row.get("tenantId"))
        .containsExactly(ops.tenantId().toString());
    TestAccount admin = TestAccounts.createInTenant(
        owner, ops.tenantId(), "hold-admin", Set.of("TRUST_ADMIN"));
    assertThatThrownBy(() -> putHold(admin, UUID.randomUUID(), true))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
    TestAccount otherTenantAdmin = TestAccounts.create(
        owner, "hold-other-admin", Set.of("TRUST_ADMIN"));
    assertThatThrownBy(() -> putHold(admin, otherTenantAdmin.tenantId(), true))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
    assertThat(owner.queryForObject(
        "SELECT legal_hold FROM tenant WHERE id = ?", Boolean.class,
        otherTenantAdmin.tenantId())).isFalse();
    assertThatThrownBy(() -> putHold(otherTenantAdmin, ops.tenantId(), true))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
  }

  private void setHold(TestAccount admin, UUID tenantId, boolean held) {
    Map<String, Object> body = putHold(admin, tenantId, held);
    assertThat(body.get("legalHold")).isEqualTo(held);
  }

  private Map<String, Object> putHold(TestAccount caller, UUID tenantId, boolean held) {
    return client.put().uri("/api/tenants/" + tenantId + "/legal-hold")
        .headers(caller.headers()).body(Map.of("held", held))
        .retrieve().body(Map.class);
  }

  private String store(TestAccount issuer, String content) {
    Map<String, Object> stored = post("/api/vault/objects", issuer.headers(), Map.of(
        "issuerId", "https://issuer.example/hold-1",
        "purposes", List.of("retention-probe"),
        "contentBase64",
        Base64.getEncoder().encodeToString(content.getBytes(StandardCharsets.UTF_8))));
    return stored.get("objectId").toString();
  }

  private String versionStatus(String objectId) {
    return owner.queryForObject(
        "SELECT status FROM vault_object_version WHERE object_id = ? AND version = 1",
        String.class, UUID.fromString(objectId));
  }

  private UUID seedAudit(UUID tenant, Instant occurredAt, String action) {
    return owner.queryForObject(
        "INSERT INTO audit_event (tenant_id, occurred_at, actor_type, actor_id, action,"
            + " resource_type, decision, reason_code, policy_version)"
            + " VALUES (?, ?, 'service', 'hold-test', ?, 'probe', 'ALLOW', 'ok', 1)"
            + " RETURNING id",
        UUID.class,
        tenant, java.sql.Timestamp.from(occurredAt), action);
  }

  private String eventTable(UUID eventId) {
    Integer live = owner.queryForObject(
        "SELECT COUNT(*) FROM audit_event WHERE id = ?", Integer.class, eventId);
    if (live != null && live == 1) {
      return "audit_event";
    }
    Integer archived = owner.queryForObject(
        "SELECT COUNT(*) FROM audit_event_archive WHERE id = ?", Integer.class, eventId);
    if (archived != null && archived == 1) {
      return "audit_event_archive";
    }
    return "missing";
  }

  private Map<String, Object> post(
      String uri, Consumer<HttpHeaders> headers, Map<String, Object> body) {
    return client.post().uri(uri).headers(headers).body(body).retrieve().body(Map.class);
  }
}
