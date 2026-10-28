package dev.sovra.quarantine;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraPostgresBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.postgresql.util.PSQLException;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Isolated-worker containment (SOV-017, SR-30, MC-02): the worker
 * role reads the cross-tenant scan queue and advances verdicts on
 * unscanned rows only. Rejected, clean, and promoted rows are
 * untouchable, non-verdict columns are unwritable, and credentials,
 * keys, grants, trust, audit, and tenants are invisible. Raw JDBC as
 * the worker role, so the database — not application code — is the
 * control under test.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class QuarantineWorkerContainmentTests extends SovraPostgresBase {

  private Connection worker;
  private JdbcTemplate owner;

  @BeforeEach
  void open() throws Exception {
    worker = quarantineRoleDataSource().getConnection();
    owner = new JdbcTemplate(ownerDataSource());
  }

  @AfterEach
  void close() throws Exception {
    if (worker != null) {
      worker.close();
    }
  }

  private UUID seedAdmission(String status) {
    TestAccount ops = TestAccounts.create(owner, "quar-seed-" + UUID.randomUUID(), Set.of());
    UUID objectId = UUID.randomUUID();
    owner.update(
        "INSERT INTO vault_object (id, tenant_id, issuer_id, created_by)"
            + " VALUES (?, ?, 'https://issuer.example/q', 'seed')",
        objectId, ops.tenantId());
    owner.update(
        "INSERT INTO vault_object_version (object_id, version, tenant_id, issuer_id,"
            + " authorized_purposes, content_sha256, kek_version, wrapped_dek, dek_nonce,"
            + " content_nonce, ciphertext, created_by)"
            + " VALUES (?, 1, ?, 'https://issuer.example/q',"
            + " ARRAY['quarantine-scan'], '\\x00', 1, '\\x00', '\\x00', '\\x00',"
            + " '\\x00', 'seed')",
        objectId, ops.tenantId());
    UUID admission = UUID.randomUUID();
    owner.update(
        "INSERT INTO quarantine_admission (id, tenant_id, vault_object_id, actual_type,"
            + " size_bytes, content_sha256, status, created_by)"
            + " VALUES (?, ?, ?, 'png', 8, '\\x00', ?, 'seed')",
        admission, ops.tenantId(), objectId, status);
    return admission;
  }

  private String admissionStatus(UUID admission) {
    return owner.queryForObject(
        "SELECT status FROM quarantine_admission WHERE id = ?", String.class, admission);
  }

  @Test
  void workerReadsQueueAcrossTenants() throws Exception {
    UUID first = seedAdmission("QUARANTINED");
    UUID second = seedAdmission("QUARANTINED");
    try (Statement stmt = worker.createStatement();
        ResultSet rs = stmt.executeQuery(
            "SELECT id FROM quarantine_admission WHERE id IN ('" + first + "', '" + second
                + "')")) {
      assertThat(rs.next()).isTrue();
      assertThat(rs.next()).isTrue();
      assertThat(rs.next()).isFalse();
    }
  }

  @Test
  void workerAdvancesUnscannedRows() throws Exception {
    UUID admission = seedAdmission("QUARANTINED");
    int updated;
    try (Statement stmt = worker.createStatement()) {
      updated = stmt.executeUpdate(
          "UPDATE quarantine_admission SET status = 'SCANNING' WHERE id = '" + admission + "'");
    }
    assertThat(updated).isEqualTo(1);
    try (Statement stmt = worker.createStatement()) {
      updated = stmt.executeUpdate(
          "UPDATE quarantine_admission SET status = 'CLEAN', verdict = 'clean',"
              + " image_width = 8, image_height = 8, scanned_at = now()"
              + " WHERE id = '" + admission + "'");
    }
    assertThat(updated).isEqualTo(1);
    assertThat(admissionStatus(admission)).isEqualTo("CLEAN");
  }

  @Test
  void workerCannotFlipRejectedToClean() throws Exception {
    UUID admission = seedAdmission("REJECTED");
    int updated;
    try (Statement stmt = worker.createStatement()) {
      // RLS hides the row from the UPDATE: zero rows, silent by
      // design, and the verdict stands.
      updated = stmt.executeUpdate(
          "UPDATE quarantine_admission SET status = 'CLEAN', verdict = 'clean'"
              + " WHERE id = '" + admission + "'");
    }
    assertThat(updated).isEqualTo(0);
    assertThat(admissionStatus(admission)).isEqualTo("REJECTED");
  }

  @Test
  void workerCannotTouchCleanOrPromotedRows() throws Exception {
    UUID clean = seedAdmission("CLEAN");
    UUID promoted = seedAdmission("PROMOTED");
    try (Statement stmt = worker.createStatement()) {
      assertThat(stmt.executeUpdate(
              "UPDATE quarantine_admission SET status = 'REJECTED' WHERE id = '" + clean + "'"))
          .isEqualTo(0);
      assertThat(stmt.executeUpdate(
              "UPDATE quarantine_admission SET status = 'QUARANTINED' WHERE id = '" + promoted
                  + "'"))
          .isEqualTo(0);
    }
    assertThat(admissionStatus(clean)).isEqualTo("CLEAN");
    assertThat(admissionStatus(promoted)).isEqualTo("PROMOTED");
  }

  @Test
  void workerCannotRewriteIdentityColumns() {
    UUID admission = seedAdmission("QUARANTINED");
    assertThatThrownBy(() -> {
      try (Statement stmt = worker.createStatement()) {
        stmt.executeUpdate("UPDATE quarantine_admission SET tenant_id = tenant_id"
            + " WHERE id = '" + admission + "'");
      }
    }).isInstanceOf(PSQLException.class).hasMessageContaining("permission denied");
    assertThatThrownBy(() -> {
      try (PreparedStatement insert = worker.prepareStatement(
          "INSERT INTO quarantine_admission (tenant_id, vault_object_id, actual_type,"
              + " size_bytes, content_sha256, created_by)"
              + " SELECT tenant_id, vault_object_id, 'png', 8, '\\x00', 'worker'"
              + " FROM quarantine_admission WHERE id = ?")) {
        insert.setObject(1, admission);
        insert.executeUpdate();
      }
    }).isInstanceOf(PSQLException.class).hasMessageContaining("permission denied");
  }

  @Test
  void workerSeesSealColumnsOnly() throws Exception {
    UUID admission = seedAdmission("QUARANTINED");
    UUID objectId = owner.queryForObject(
        "SELECT vault_object_id FROM quarantine_admission WHERE id = ?", UUID.class, admission);
    try (Statement stmt = worker.createStatement();
        ResultSet rs = stmt.executeQuery(
            "SELECT ciphertext, wrapped_dek, content_sha256 FROM vault_object_version"
                + " WHERE object_id = '" + objectId + "'")) {
      assertThat(rs.next()).isTrue();
    }
    assertThatThrownBy(() -> {
      try (Statement stmt = worker.createStatement()) {
        stmt.executeQuery("SELECT created_by FROM vault_object_version LIMIT 1");
      }
    }).isInstanceOf(PSQLException.class).hasMessageContaining("permission denied");
    assertThatThrownBy(() -> {
      try (Statement stmt = worker.createStatement()) {
        stmt.executeQuery("SELECT display_name FROM vault_object LIMIT 1");
      }
    }).isInstanceOf(PSQLException.class).hasMessageContaining("permission denied");
  }

  @Test
  void workerSeesNoCredentialsKeysGrantsTrustAuditOrTenants() {
    for (String table : new String[] {
        "service_account", "human_membership", "credential_artifact", "issuer_signing_key",
        "issuer_key_revocation", "vault_kek", "vault_grant", "issuer_record", "rp_policy",
        "trust_change_proposal", "trust_proposal_decision", "trust_snapshot",
        "trust_snapshot_activation", "audit_event", "tenant", "proof_request",
        "verification_decision", "issuance_idempotency", "emergency_flag"}) {
      assertThatThrownBy(() -> {
        try (Statement stmt = worker.createStatement()) {
          stmt.executeQuery("SELECT * FROM " + table + " LIMIT 1");
        }
      }).as("worker access to " + table)
          .isInstanceOf(PSQLException.class)
          .hasMessageContaining("permission denied");
    }
  }
}
