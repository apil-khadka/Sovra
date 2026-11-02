package dev.sovra.retention;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraPostgresBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.postgresql.util.PSQLException;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Transient retention (PROD-010): expired grants, idempotency
 * mappings, and protocol rows reap through the SECURITY DEFINER
 * maintenance functions as the least-privilege role; fresh rows
 * and the 24-hour forensic grace window survive; direct DELETE
 * stays denied.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class TransientPurgeTests extends SovraPostgresBase {

  JdbcTemplate owner;
  JdbcTemplate app;
  UUID tenant;
  UUID account;

  @BeforeEach
  void setup() {
    owner = new JdbcTemplate(ownerDataSource());
    app = new JdbcTemplate(appRoleDataSource());
    owner.update("DELETE FROM tenant WHERE slug = 'purge-probe'");
    tenant =
        owner.queryForObject(
            "INSERT INTO tenant (slug, display_name) VALUES ('purge-probe', 'Purge probe')"
                + " RETURNING id",
            UUID.class);
    TestAccount ops = TestAccounts.createInTenant(owner, tenant, "purge-ops", Set.of());
    account = ops.accountId();
  }

  @AfterEach
  void cleanup() {
    owner.update("DELETE FROM vp_session WHERE tenant_id = ?", tenant);
    owner.update("DELETE FROM vci_token WHERE tenant_id = ?", tenant);
    owner.update("DELETE FROM vci_grant WHERE tenant_id = ?", tenant);
    owner.update("DELETE FROM issuance_idempotency WHERE tenant_id = ?", tenant);
    owner.update("DELETE FROM vault_grant WHERE tenant_id = ?", tenant);
    owner.update("DELETE FROM vault_object_version WHERE tenant_id = ?", tenant);
    owner.update("DELETE FROM vault_object WHERE tenant_id = ?", tenant);
    owner.update("DELETE FROM proof_request WHERE tenant_id = ?", tenant);
    owner.update("DELETE FROM credential_artifact WHERE tenant_id = ?", tenant);
    owner.update("DELETE FROM service_account WHERE tenant_id = ?", tenant);
    owner.update("DELETE FROM tenant WHERE id = ?", tenant);
  }

  @Test
  void purgeReapsExpiredAndKeepsFresh() {
    UUID credential = seedCredential();
    UUID request = seedRequest(credential);
    seedGrants();
    seedIdempotency(credential);
    seedVci();
    seedVpSessions(request);

    new TransientPurge(appRoleDataSource()).purge();

    assertThat(count("vault_grant")).isEqualTo(1);
    assertThat(count("issuance_idempotency")).isEqualTo(1);
    assertThat(count("vci_grant")).isEqualTo(2);
    assertThat(count("vci_token")).isEqualTo(2);
    assertThat(count("vp_session")).isEqualTo(2);
  }

  @Test
  void directDeleteStaysDenied() throws Exception {
    // Maintenance-role separation: the app role EXECUTEs the purge
    // functions but holds no DELETE on the tables themselves. The
    // tenant pin comes first so the denial is the missing grant,
    // not the strict tenant guard — on one held connection, so no
    // pool slot leaks the pin.
    try (java.sql.Connection con = appRoleDataSource().getConnection();
        java.sql.Statement pin = con.createStatement()) {
      pin.execute("SET app.tenant = '" + tenant + "'");
      for (String table : new String[] {"vault_grant", "vci_grant", "vp_session"}) {
        try (java.sql.Statement attempt = con.createStatement()) {
          assertThatThrownBy(() -> attempt.executeUpdate("DELETE FROM " + table))
              .isInstanceOf(PSQLException.class)
              .hasMessageContaining("permission denied");
        }
      }
    }
  }

  @Test
  void purgeFunctionsAreExecutableAsAppRole() {
    assertThat(
            app.queryForObject("SELECT purge_expired_vault_grants(1000)", Integer.class))
        .isNotNull();
    assertThat(
            app.queryForObject("SELECT purge_expired_issuance_idempotency(1000)", Integer.class))
        .isNotNull();
    assertThat(app.queryForObject("SELECT purge_expired_vci_grants(1000)", Integer.class))
        .isNotNull();
    assertThat(app.queryForObject("SELECT purge_expired_vci_tokens(1000)", Integer.class))
        .isNotNull();
    assertThat(app.queryForObject("SELECT purge_expired_vp_sessions(1000)", Integer.class))
        .isNotNull();
  }

  private int count(String table) {
    return owner.queryForObject(
        "SELECT COUNT(*) FROM " + table + " WHERE tenant_id = ?", Integer.class, tenant);
  }

  private UUID seedCredential() {
    return owner.queryForObject(
        "INSERT INTO credential_artifact (tenant_id, issuer_id, vct, holder_thumbprint,"
            + " key_ref, expires_at, artifact, trust_snapshot_version, created_by)"
            + " VALUES (?, 'issuer-1', 'AgeOver18', 'thumb', 'key-1',"
            + " now() + interval '1 year', '{}', 1, 'purge-test') RETURNING id",
        UUID.class, tenant);
  }

  private UUID seedRequest(UUID credential) {
    return owner.queryForObject(
        "INSERT INTO proof_request (tenant_id, credential_id, rp_id, audience, purpose,"
            + " claims, plan_hash, challenge, holder_thumbprint, expires_at,"
            + " trust_snapshot_version, created_by)"
            + " VALUES (?, ?, 'rp-1', 'aud-1', 'age-check', '{}',"
            + " md5('a') || md5('b'), 'challenge-' || md5('c'), 'thumb',"
            + " now() + interval '1 hour', 1, 'purge-test') RETURNING id",
        UUID.class, tenant, credential);
  }

  private void seedGrants() {
    UUID objectId = UUID.randomUUID();
    owner.update(
        "INSERT INTO vault_object (id, tenant_id, issuer_id, created_by)"
            + " VALUES (?, ?, 'https://issuer.example/q', 'seed')",
        objectId, tenant);
    owner.update(
        "INSERT INTO vault_object_version (object_id, version, tenant_id, issuer_id,"
            + " authorized_purposes, content_sha256, kek_version, wrapped_dek, dek_nonce,"
            + " content_nonce, ciphertext, created_by)"
            + " VALUES (?, 1, ?, 'https://issuer.example/q',"
            + " ARRAY['quarantine-scan'], '\\x00', 1, '\\x00', '\\x00', '\\x00',"
            + " '\\x00', 'seed')",
        objectId, tenant);
    // The grant CHECK requires expiry after creation, so the
    // expired row is inserted fresh and backdated as the owner.
    for (int i = 0; i < 2; i++) {
      owner.update(
          "INSERT INTO vault_grant (tenant_id, object_id, object_version, principal_type,"
              + " principal_id, purpose, workload, expires_at, created_by)"
              + " VALUES (?, ?, 1, 'service_account', ?, 'read', 'test',"
              + " now() + interval '1 hour', 't')",
          tenant, objectId, account);
    }
    owner.update(
        "UPDATE vault_grant SET created_at = now() - interval '2 hours',"
            + " expires_at = now() - interval '1 hour'"
            + " WHERE tenant_id = ? AND id IN"
            + " (SELECT id FROM vault_grant WHERE tenant_id = ? LIMIT 1)",
        tenant, tenant);
  }

  private void seedIdempotency(UUID credential) {
    owner.update(
        "INSERT INTO issuance_idempotency (tenant_id, idempotency_key, credential_id,"
            + " request_hash, response_body, expires_at)"
            + " VALUES (?, 'key-old', ?, 'h', '{}', now() - interval '1 hour')",
        tenant, credential);
    owner.update(
        "INSERT INTO issuance_idempotency (tenant_id, idempotency_key, credential_id,"
            + " request_hash, response_body, expires_at)"
            + " VALUES (?, 'key-fresh', ?, 'h', '{}', now() + interval '1 hour')",
        tenant, credential);
  }

  private void seedVci() {
    // One long-expired (reaped), one inside the 24-hour grace
    // window (kept), one fresh (kept).
    String[] expiries = {
      "now() - interval '25 hours'", "now() - interval '1 hour'", "now() + interval '1 hour'"
    };
    for (int i = 0; i < expiries.length; i++) {
      UUID grant =
          owner.queryForObject(
              "INSERT INTO vci_grant (tenant_id, kind, issuer_id, vct, code_hash,"
                  + " created_by, created_account, expires_at)"
                  + " VALUES (?, 'PRE_AUTH', 'issuer-1', 'AgeOver18', ?, 't', ?, "
                  + expiries[i] + ") RETURNING id",
              UUID.class, tenant, "code-" + i + "-" + UUID.randomUUID(), account);
      owner.update(
          "INSERT INTO vci_token (tenant_id, grant_id, token_hash, expires_at)"
              + " VALUES (?, ?, ?, " + expiries[i] + ")",
          tenant, grant, "token-" + i + "-" + UUID.randomUUID());
    }
  }

  private void seedVpSessions(UUID request) {
    String[] expiries = {
      "now() - interval '25 hours'", "now() - interval '1 hour'", "now() + interval '1 hour'"
    };
    for (int i = 0; i < expiries.length; i++) {
      owner.update(
          "INSERT INTO vp_session (tenant_id, proof_request_id, nonce, created_by,"
              + " created_account, expires_at)"
              + " VALUES (?, ?, ?, 't', ?, " + expiries[i] + ")",
          tenant, request, "nonce-" + i + "-" + UUID.randomUUID(), account);
    }
  }
}
