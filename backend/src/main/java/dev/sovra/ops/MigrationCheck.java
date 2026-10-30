package dev.sovra.ops;

import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Migration completeness: every relation the G1 flow depends on must exist.
 * information_schema is readable by every role, so this tests the actual
 * schema without touching tenant data. Table names are fixed identifiers,
 * safe to report.
 */
@Component
public class MigrationCheck implements ReadinessCheck {

  static final List<String> REQUIRED_TABLES =
      List.of(
          "tenant",
          "service_account",
          "emergency_flag",
          "audit_event",
          "trust_snapshot",
          "trust_snapshot_activation",
          "issuer_record",
          "rp_policy",
          "trust_change_proposal",
          "trust_proposal_decision",
          "issuer_signing_key",
          "credential_artifact",
          "issuance_idempotency",
          "proof_request",
          "verification_decision",
          "issuer_key_revocation",
          "human_membership",
          "vault_object",
          "vault_object_version",
          "vault_grant",
          "vault_kek",
          "quarantine_admission",
          "vci_grant",
          "vci_token",
          "vp_session",
          "extraction_record",
          "extraction_revision",
          "enrollment",
          "enrollment_review",
          "holder_key",
          "holder_recovery");

  private final JdbcTemplate global;

  public MigrationCheck(DataSource globalDataSource) {
    this.global = new JdbcTemplate(globalDataSource);
  }

  @Override
  public String name() {
    return "migrations";
  }

  @Override
  public CheckResult check() {
    long start = System.nanoTime();
    try {
      List<String> present =
          global.query(
              "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
              (rs, row) -> rs.getString(1));
      long durationMs = DatabaseCheck.elapsedMs(start);
      List<String> missing = REQUIRED_TABLES.stream().filter(t -> !present.contains(t)).toList();
      if (missing.isEmpty()) {
        return CheckResult.up(
            name(), "schema_complete", Map.of("tables", REQUIRED_TABLES.size()), durationMs);
      }
      return CheckResult.down(
          name(), "schema_incomplete", Map.of("missing", missing.size()), durationMs);
    } catch (Exception e) {
      return CheckResult.down(name(), "unreachable", Map.of(), DatabaseCheck.elapsedMs(start));
    }
  }
}
