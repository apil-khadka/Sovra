package dev.sovra.tenancy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraPostgresBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.auth.ServiceAccountPrincipal;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.postgresql.util.PSQLException;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Database-level enforcement for the least-privilege role: RLS tenant
 * isolation with a strict setting, and grant denials on every table the
 * app role may read or append but never rewrite. Raw JDBC on one pinned
 * connection per test, because session settings must not cross borrows.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class LeastPrivilegeTests extends SovraPostgresBase {

  private Connection app;
  private JdbcTemplate owner;

  @BeforeEach
  void open() throws Exception {
    app = appRoleDataSource().getConnection();
    owner = new JdbcTemplate(ownerDataSource());
  }

  @AfterEach
  void close() throws Exception {
    if (app != null) {
      // Return the connection unpinned: a pooled session otherwise keeps
      // its tenant setting for the next borrower (production borrows go
      // through TenantDataSource, which resets on close by construction).
      try (Statement stmt = app.createStatement()) {
        stmt.execute("RESET app.tenant");
      }
      app.close();
    }
  }

  private void setTenant(UUID tenantId) throws Exception {
    try (Statement stmt = app.createStatement()) {
      stmt.execute("SET app.tenant = '" + tenantId + "'");
    }
  }

  private List<UUID> auditTenants() throws Exception {
    try (Statement stmt = app.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT tenant_id FROM audit_event")) {
      List<UUID> ids = new ArrayList<>();
      while (rs.next()) {
        ids.add(rs.getObject(1, UUID.class));
      }
      return ids;
    }
  }

  private void seedAudit(UUID tenantId) {
    owner.update(
        "INSERT INTO audit_event (tenant_id, actor_type, actor_id, action, resource_type,"
            + " decision, reason_code, policy_version) VALUES (?, 't', 'a', 'ACT', 'r', 'PERMIT',"
            + " 'PERMIT', 1)",
        tenantId);
  }

  @Test
  void appRoleSeesOnlyOwnTenantRows() throws Exception {
    TestAccount accountA = TestAccounts.create(owner, "rls-a", Set.of("TENANT_MEMBER"));
    TestAccount accountB = TestAccounts.create(owner, "rls-b", Set.of("TENANT_MEMBER"));
    seedAudit(accountA.tenantId());
    seedAudit(accountB.tenantId());

    setTenant(accountA.tenantId());
    assertThat(auditTenants()).containsExactly(accountA.tenantId());
    setTenant(accountB.tenantId());
    assertThat(auditTenants()).containsExactly(accountB.tenantId());
  }

  @Test
  void missingTenantSettingFailsInsteadOfLeaking() throws Exception {
    // Pooled connections may arrive with a prior setting; RESET reaches
    // the empty state, which the guard must refuse loudly.
    try (Statement stmt = app.createStatement()) {
      stmt.execute("RESET app.tenant");
    }
    assertThatThrownBy(this::auditTenants)
        .isInstanceOf(PSQLException.class)
        .hasMessageContaining("app.tenant is not set");
  }

  @Test
  void resetConnectionStillFailsInsteadOfLeaking() throws Exception {
    // Hold one pool connection raw, pin the other through the tenant
    // wrapper, then close it: RESET leaves the setting defined-but-empty,
    // and a later raw borrow of that same connection must still refuse.
    TestAccount account = TestAccounts.create(owner, "reset-empty", Set.of("TENANT_MEMBER"));
    TenantContext.set(
        new ServiceAccountPrincipal(
            account.accountId(), account.tenantId(), account.name(), account.roles()));
    try {
      new JdbcTemplate(new TenantDataSource(appRoleDataSource())).queryForList("SELECT 1");
    } finally {
      TenantContext.clear();
    }
    try (Connection recycled = appRoleDataSource().getConnection();
        Statement stmt = recycled.createStatement()) {
      assertThatThrownBy(() -> stmt.executeQuery("SELECT tenant_id FROM audit_event"))
          .isInstanceOf(PSQLException.class)
          .hasMessageContaining("app.tenant is not set");
    }
  }

  @Test
  void appRoleCannotRewriteAudit() throws Exception {
    TestAccount account = TestAccounts.create(owner, "frozen", Set.of("TENANT_MEMBER"));
    seedAudit(account.tenantId());
    setTenant(account.tenantId());
    assertThatThrownBy(
            () -> {
              try (Statement stmt = app.createStatement()) {
                stmt.executeUpdate("UPDATE audit_event SET decision = 'DENY'");
              }
            })
        .isInstanceOf(PSQLException.class)
        .hasMessageContaining("permission denied");
    assertThatThrownBy(
            () -> {
              try (Statement stmt = app.createStatement()) {
                stmt.executeUpdate("DELETE FROM audit_event");
              }
            })
        .isInstanceOf(PSQLException.class)
        .hasMessageContaining("permission denied");
  }

  @Test
  void appRoleCannotRewriteTrust() {
    assertThatThrownBy(
            () -> {
              try (Statement stmt = app.createStatement()) {
                stmt.executeUpdate("UPDATE trust_snapshot SET note = 'x' WHERE version = 1");
              }
            })
        .isInstanceOf(PSQLException.class)
        .hasMessageContaining("permission denied");
    assertThatThrownBy(
            () -> {
              try (Statement stmt = app.createStatement()) {
                stmt.executeUpdate("DELETE FROM issuer_record");
              }
            })
        .isInstanceOf(PSQLException.class)
        .hasMessageContaining("permission denied");
  }

  @Test
  void appRoleCannotTouchMigrations() {
    assertThatThrownBy(
            () -> {
              try (Statement stmt = app.createStatement()) {
                stmt.executeQuery("SELECT * FROM flyway_schema_history LIMIT 1");
              }
            })
        .isInstanceOf(PSQLException.class)
        .hasMessageContaining("permission denied");
  }

  @Test
  void appRoleSeesOnlyOwnTenantCredentials() throws Exception {
    TestAccount accountA = TestAccounts.create(owner, "cred-a", Set.of("ISSUER_OPS"));
    TestAccount accountB = TestAccounts.create(owner, "cred-b", Set.of("ISSUER_OPS"));
    UUID idA = seedCredential(accountA);
    UUID idB = seedCredential(accountB);

    setTenant(accountA.tenantId());
    assertThat(credentialIds()).containsExactly(idA);
    setTenant(accountB.tenantId());
    assertThat(credentialIds()).containsExactly(idB);
  }

  private UUID seedCredential(TestAccount account) {
    return owner.queryForObject(
        "INSERT INTO credential_artifact (tenant_id, issuer_id, vct, holder_thumbprint,"
            + " key_ref, expires_at, artifact, trust_snapshot_version, created_by)"
            + " VALUES (?, 'i', 'v', 'h', 'k', now() + INTERVAL '1 hour', 'a', 1, 't')"
            + " RETURNING id",
        UUID.class,
        account.tenantId());
  }

  private List<UUID> credentialIds() throws Exception {
    try (Statement stmt = app.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT id FROM credential_artifact")) {
      List<UUID> ids = new ArrayList<>();
      while (rs.next()) {
        ids.add(rs.getObject(1, UUID.class));
      }
      return ids;
    }
  }

  @Test
  void appRoleCanOnlyRevokeCredentials() throws Exception {
    TestAccount account = TestAccounts.create(owner, "revoke-only", Set.of("ISSUER_OPS"));
    UUID id = seedCredential(account);
    setTenant(account.tenantId());
    assertThatThrownBy(
            () -> {
              try (Statement stmt = app.createStatement()) {
                stmt.executeUpdate(
                    "UPDATE credential_artifact SET artifact = 'x' WHERE id = '" + id + "'");
              }
            })
        .isInstanceOf(PSQLException.class)
        .hasMessageContaining("permission denied");
    assertThatThrownBy(
            () -> {
              try (Statement stmt = app.createStatement()) {
                stmt.executeUpdate("DELETE FROM credential_artifact WHERE id = '" + id + "'");
              }
            })
        .isInstanceOf(PSQLException.class)
        .hasMessageContaining("permission denied");
    try (Statement stmt = app.createStatement()) {
      int updated =
          stmt.executeUpdate(
              "UPDATE credential_artifact SET status = 'REVOKED' WHERE id = '" + id + "'");
      assertThat(updated).isEqualTo(1);
    }
  }

  @Test
  void appRoleCannotRewriteSigningKeys() throws Exception {
    TestAccount account = TestAccounts.create(owner, "key-guard", Set.of("ISSUER_OPS"));
    setTenant(account.tenantId());
    assertThatThrownBy(
            () -> {
              try (Statement stmt = app.createStatement()) {
                stmt.executeUpdate("UPDATE issuer_signing_key SET status = 'REVOKED'");
              }
            })
        .isInstanceOf(PSQLException.class)
        .hasMessageContaining("permission denied");
    assertThatThrownBy(
            () -> {
              try (Statement stmt = app.createStatement()) {
                stmt.executeUpdate("DELETE FROM issuer_signing_key");
              }
            })
        .isInstanceOf(PSQLException.class)
        .hasMessageContaining("permission denied");
  }

  @Test
  void appRoleMayBumpCredentialStatusVersion() throws Exception {
    TestAccount account = TestAccounts.create(owner, "status-ver", Set.of("ISSUER_OPS"));
    UUID id = seedCredential(account);
    setTenant(account.tenantId());
    // The terminal revocation flip and its version bump are the only
    // credential writes; artifact and identity columns stay frozen.
    try (Statement stmt = app.createStatement()) {
      int updated =
          stmt.executeUpdate(
              "UPDATE credential_artifact SET status = 'REVOKED',"
                  + " status_version = status_version + 1 WHERE id = '" + id + "'");
      assertThat(updated).isEqualTo(1);
    }
    Long version =
        owner.queryForObject(
            "SELECT status_version FROM credential_artifact WHERE id = ?", Long.class, id);
    assertThat(version).isEqualTo(2);
  }

  @Test
  void appRoleRevocationsAreTerminalByGrants() throws Exception {
    TestAccount account = TestAccounts.create(owner, "rev-term", Set.of("ISSUER_OPS"));
    setTenant(account.tenantId());
    // Reads see the live revocation state every caller honors.
    try (Statement stmt = app.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM issuer_key_revocation")) {
      rs.next();
      assertThat(rs.getInt(1)).isGreaterThanOrEqualTo(0);
    }
    // New revocations append; nothing rewrites or removes one.
    try (Statement stmt = app.createStatement()) {
      int inserted =
          stmt.executeUpdate(
              "INSERT INTO issuer_key_revocation"
                  + " (issuer_id, key_id, key_version, revoked_by, reason)"
                  + " VALUES ('test-issuer', 'test-key', 1, 'least-privilege', 'drill')");
      assertThat(inserted).isEqualTo(1);
    }
    try {
      assertThatThrownBy(
              () -> {
                try (Statement stmt = app.createStatement()) {
                  stmt.executeUpdate(
                      "UPDATE issuer_key_revocation SET reason = 'x'"
                          + " WHERE issuer_id = 'test-issuer'");
                }
              })
          .isInstanceOf(PSQLException.class)
          .hasMessageContaining("permission denied");
      assertThatThrownBy(
              () -> {
                try (Statement stmt = app.createStatement()) {
                  stmt.executeUpdate("DELETE FROM issuer_key_revocation");
                }
              })
          .isInstanceOf(PSQLException.class)
          .hasMessageContaining("permission denied");
    } finally {
      owner.update("DELETE FROM issuer_key_revocation WHERE issuer_id = 'test-issuer'");
    }
  }

  @Test
  void appRoleSeesOnlyOwnTenantProofRequests() throws Exception {
    TestAccount accountA = TestAccounts.create(owner, "cons-a", Set.of("RP_CLIENT"));
    TestAccount accountB = TestAccounts.create(owner, "cons-b", Set.of("RP_CLIENT"));
    UUID idA = seedProofRequest(accountA);
    UUID idB = seedProofRequest(accountB);

    setTenant(accountA.tenantId());
    assertThat(proofRequestIds()).containsExactly(idA);
    setTenant(accountB.tenantId());
    assertThat(proofRequestIds()).containsExactly(idB);
  }

  @Test
  void appRoleCanOnlyDecideProofRequests() throws Exception {
    TestAccount account = TestAccounts.create(owner, "cons-decide", Set.of("RP_CLIENT"));
    UUID id = seedProofRequest(account);
    setTenant(account.tenantId());
    // Bound scope is immutable: purpose, claims, and bindings cannot move.
    assertThatThrownBy(
            () -> {
              try (Statement stmt = app.createStatement()) {
                stmt.executeUpdate(
                    "UPDATE proof_request SET purpose = 'x' WHERE id = '" + id + "'");
              }
            })
        .isInstanceOf(PSQLException.class)
        .hasMessageContaining("permission denied");
    assertThatThrownBy(
            () -> {
              try (Statement stmt = app.createStatement()) {
                stmt.executeUpdate("DELETE FROM proof_request WHERE id = '" + id + "'");
              }
            })
        .isInstanceOf(PSQLException.class)
        .hasMessageContaining("permission denied");
    // Only the terminal decision columns are writable.
    try (Statement stmt = app.createStatement()) {
      int updated =
          stmt.executeUpdate(
              "UPDATE proof_request SET state = 'DENIED', decided_at = now(),"
                  + " consent_artifact = 'p' WHERE id = '"
                  + id + "'");
      assertThat(updated).isEqualTo(1);
    }
  }

  private UUID seedProofRequest(TestAccount account) {
    UUID credentialId = seedCredential(account);
    return owner.queryForObject(
        "INSERT INTO proof_request (tenant_id, credential_id, rp_id, audience, purpose,"
            + " claims, plan_hash, challenge, holder_thumbprint, expires_at,"
            + " trust_snapshot_version, created_by)"
            + " VALUES (?, ?, 'rp', 'aud', 'purpose', '{\"adultOver18\":true}',"
            + " '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',"
            + " '0123456789abcdef0123456789abcdef', 'holder',"
            + " now() + INTERVAL '1 hour', 1, 't')"
            + " RETURNING id",
        UUID.class,
        account.tenantId(),
        credentialId);
  }

  private List<UUID> proofRequestIds() throws Exception {
    try (Statement stmt = app.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT id FROM proof_request")) {
      List<UUID> ids = new ArrayList<>();
      while (rs.next()) {
        ids.add(rs.getObject(1, UUID.class));
      }
      return ids;
    }
  }

  @Test
  void appRoleSeesOnlyOwnTenantDecisions() throws Exception {
    TestAccount accountA = TestAccounts.create(owner, "ver-a", Set.of("RP_CLIENT"));
    TestAccount accountB = TestAccounts.create(owner, "ver-b", Set.of("RP_CLIENT"));
    UUID idA = seedVerificationDecision(accountA);
    UUID idB = seedVerificationDecision(accountB);

    setTenant(accountA.tenantId());
    assertThat(decisionIds()).containsExactly(idA);
    setTenant(accountB.tenantId());
    assertThat(decisionIds()).containsExactly(idB);
  }

  @Test
  void appRoleCannotRewriteDecisions() throws Exception {
    TestAccount account = TestAccounts.create(owner, "ver-frozen", Set.of("RP_CLIENT"));
    UUID id = seedVerificationDecision(account);
    setTenant(account.tenantId());
    // Stored decisions are immutable: no outcome, reason, or response
    // rewrite, and no deletion — follow-ups are separate records.
    assertThatThrownBy(
            () -> {
              try (Statement stmt = app.createStatement()) {
                stmt.executeUpdate(
                    "UPDATE verification_decision SET outcome = 'ACCEPTED' WHERE id = '" + id
                        + "'");
              }
            })
        .isInstanceOf(PSQLException.class)
        .hasMessageContaining("permission denied");
    assertThatThrownBy(
            () -> {
              try (Statement stmt = app.createStatement()) {
                stmt.executeUpdate("DELETE FROM verification_decision WHERE id = '" + id + "'");
              }
            })
        .isInstanceOf(PSQLException.class)
        .hasMessageContaining("permission denied");
  }

  private UUID seedVerificationDecision(TestAccount account) {
    UUID requestId = seedProofRequest(account);
    UUID credentialId =
        owner.queryForObject(
            "SELECT credential_id FROM proof_request WHERE id = ?", UUID.class, requestId);
    return owner.queryForObject(
        "INSERT INTO verification_decision (tenant_id, request_id, credential_id, nonce,"
            + " request_hash, rp_id, audience, outcome, reason_code, response_body,"
            + " trust_snapshot_version, decided_by)"
            + " VALUES (?, ?, ?, '0123456789abcdef0123456789abcdef', 'hash', 'rp', 'aud',"
            + " 'REJECTED', 'CONSENT_NOT_APPROVED', '{}', 1, 't')"
            + " RETURNING id",
        UUID.class,
        account.tenantId(),
        requestId,
        credentialId);
  }

  private List<UUID> decisionIds() throws Exception {
    try (Statement stmt = app.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT id FROM verification_decision")) {
      List<UUID> ids = new ArrayList<>();
      while (rs.next()) {
        ids.add(rs.getObject(1, UUID.class));
      }
      return ids;
    }
  }

  @Test
  void appRoleCanReadAccountsForAuthentication() throws Exception {
    TestAccounts.create(owner, "readable", Set.of("TENANT_MEMBER"));
    try (Statement stmt = app.createStatement();
        ResultSet rs =
            stmt.executeQuery("SELECT COUNT(*) FROM service_account WHERE revoked = FALSE")) {
      rs.next();
      assertThat(rs.getInt(1)).isGreaterThanOrEqualTo(1);
    }
  }
}
