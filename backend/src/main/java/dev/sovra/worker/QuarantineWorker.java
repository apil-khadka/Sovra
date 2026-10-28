package dev.sovra.worker;

import dev.sovra.quarantine.QuarantineSniff;
import dev.sovra.vault.VaultCrypto;
import dev.sovra.vault.VaultEnvelope;
import dev.sovra.vault.VaultKekProvider;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;

/**
 * Quarantine scan worker (SOV-017). Framework-free by design: plain
 * JDBC against the least-privilege worker role, one admission per
 * transaction, envelope opens through the KMS-shaped provider seam.
 * The worker holds no credentials, no keys, no trust access, and no
 * HTTP clients — compromise of this process cannot reach the signer,
 * other tenants' bytes, or the network through this code.
 */
public class QuarantineWorker {

  private final DataSource dataSource;
  private final VaultKekProvider kek;

  public QuarantineWorker(DataSource dataSource, VaultKekProvider kek) {
    this.dataSource = dataSource;
    this.kek = kek;
  }

  /** Claims and scans one admission; empty when the queue is idle. */
  public boolean scanOne() throws Exception {
    try (Connection con = dataSource.getConnection()) {
      con.setAutoCommit(false);
      UUID admission = claim(con);
      if (admission == null) {
        con.rollback();
        return false;
      }
      try {
        scanClaimed(con, admission);
        con.commit();
      } catch (Exception e) {
        con.rollback();
        throw e;
      }
      return true;
    }
  }

  private UUID claim(Connection con) throws Exception {
    // Single-statement atomic claim: SELECT ... FOR UPDATE would need
    // table-level UPDATE, which the worker deliberately lacks (its
    // UPDATE grant is verdict-columns-only). Racing workers serialize
    // on the row lock; the loser re-reads a claimed row, matches
    // nothing, and retries for the next admission.
    for (int attempt = 0; attempt < 3; attempt++) {
      try (PreparedStatement claim = con.prepareStatement(
          "UPDATE quarantine_admission SET status = 'SCANNING' WHERE id = (SELECT id"
              + " FROM quarantine_admission WHERE status = 'QUARANTINED'"
              + " ORDER BY created_at LIMIT 1) AND status = 'QUARANTINED' RETURNING id")) {
        try (ResultSet rs = claim.executeQuery()) {
          if (rs.next()) {
            return rs.getObject(1, UUID.class);
          }
        }
      }
    }
    return null;
  }

  private void scanClaimed(Connection con, UUID admission) throws Exception {
    UUID tenantId;
    UUID objectId;
    String claimedType;
    try (PreparedStatement load = con.prepareStatement(
        "SELECT tenant_id, vault_object_id, claimed_type FROM quarantine_admission"
            + " WHERE id = ?")) {
      load.setObject(1, admission);
      try (ResultSet rs = load.executeQuery()) {
        rs.next();
        tenantId = rs.getObject(1, UUID.class);
        objectId = rs.getObject(2, UUID.class);
        claimedType = rs.getString(3);
      }
    }
    try (PreparedStatement scope = con.prepareStatement("SELECT set_config('app.tenant', ?, true)")) {
      scope.setString(1, tenantId.toString());
      scope.executeQuery().close();
    }
    byte[] content;
    try {
      content = openVersion(con, tenantId, objectId);
    } catch (Exception e) {
      // Sealed bytes that no longer open are hostile or corrupt, not
      // scannable: reject, never retry into plaintext.
      finish(con, admission, false, "seal-failed",
          "quarantine bytes do not authenticate", null, null);
      return;
    }
    QuarantineScanner.Verdict verdict = QuarantineScanner.scan(content);
    String detail = verdict.detail();
    if (claimedType != null && !claimedType.isBlank()
        && QuarantineSniff.actualType(content).map(actual -> !actual.equals(claimedType))
            .orElse(false)) {
      detail = "claimed type mismatches actual bytes"
          + (detail.isEmpty() ? "" : "; " + detail);
    }
    finish(con, admission, verdict.clean(), verdict.reason(), detail, verdict.width(),
        verdict.height());
  }

  private byte[] openVersion(Connection con, UUID tenantId, UUID objectId) throws Exception {
    UUID rowObject;
    int version;
    String issuerId;
    List<String> purposes;
    byte[] sha;
    int kekVersion;
    byte[] wrapped;
    byte[] dekNonce;
    byte[] contentNonce;
    byte[] ciphertext;
    String status;
    try (PreparedStatement load = con.prepareStatement(
        "SELECT object_id, version, issuer_id, authorized_purposes, content_sha256,"
            + " kek_version, wrapped_dek, dek_nonce, content_nonce, ciphertext, status"
            + " FROM vault_object_version WHERE object_id = ? AND version = 1")) {
      load.setObject(1, objectId);
      try (ResultSet rs = load.executeQuery()) {
        if (!rs.next()) {
          throw new IllegalStateException("quarantine bytes missing");
        }
        rowObject = rs.getObject(1, UUID.class);
        version = rs.getInt(2);
        issuerId = rs.getString(3);
        Array array = rs.getArray(4);
        String[] names = array == null ? new String[0] : (String[]) array.getArray();
        java.util.Arrays.sort(names);
        purposes = List.of(names);
        sha = rs.getBytes(5);
        kekVersion = rs.getInt(6);
        wrapped = rs.getBytes(7);
        dekNonce = rs.getBytes(8);
        contentNonce = rs.getBytes(9);
        ciphertext = rs.getBytes(10);
        status = rs.getString(11);
      }
    }
    if (!"VALID".equals(status)) {
      throw new IllegalStateException("quarantine bytes deleted");
    }
    byte[] dek = kek.unwrapDek(tenantId, kekVersion, wrapped, dekNonce,
        VaultEnvelope.wrapAad(tenantId, issuerId, rowObject, version, kekVersion, purposes));
    List<String> authorized = new ArrayList<>(purposes);
    if (!authorized.contains("quarantine-scan")) {
      throw new IllegalStateException("not a quarantine object");
    }
    return VaultCrypto.open(dek, contentNonce, ciphertext,
        VaultEnvelope.contentAad(tenantId, issuerId, rowObject, version, kekVersion, sha));
  }

  private void finish(
      Connection con,
      UUID admission,
      boolean clean,
      String reason,
      String detail,
      Integer width,
      Integer height) throws Exception {
    String verdict = reason + (detail == null || detail.isEmpty() ? "" : ": " + detail);
    if (verdict.length() > 512) {
      verdict = verdict.substring(0, 512);
    }
    try (PreparedStatement update = con.prepareStatement(
        "UPDATE quarantine_admission SET status = ?, verdict = ?, image_width = ?,"
            + " image_height = ?, scanned_at = now() WHERE id = ?")) {
      update.setString(1, clean ? "CLEAN" : "REJECTED");
      update.setString(2, verdict);
      if (width == null) {
        update.setNull(3, java.sql.Types.INTEGER);
      } else {
        update.setInt(3, width);
      }
      if (height == null) {
        update.setNull(4, java.sql.Types.INTEGER);
      } else {
        update.setInt(4, height);
      }
      update.setObject(5, admission);
      update.executeUpdate();
    }
  }
}
