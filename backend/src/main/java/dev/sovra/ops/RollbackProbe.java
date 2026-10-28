package dev.sovra.ops;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.sql.DataSource;

/**
 * Rollback-only write-path probe for RLS-guarded tables. Pins
 * {@code app.tenant} to a random UUID (which can never match a real tenant
 * row), attempts the INSERT, then always rolls back. Reaching the foreign-key
 * violation proves connectivity, INSERT grant, RLS evaluation, and the commit
 * path without persisting anything — including on a fresh database with no
 * tenant rows. Never throws; maps every outcome to a fixed code.
 */
final class RollbackProbe {

  /** PostgreSQL foreign_key_violation: the write path reached constraint enforcement. */
  private static final String FK_VIOLATION = "23503";

  private RollbackProbe() {}

  /**
   * @param sql INSERT with {@code tenant_id} as the first bind parameter;
   *     {@code args} are the remaining parameters. The probe pins
   *     {@code app.tenant} to the same random UUID it inserts, so the RLS
   *     WITH CHECK passes and the foreign key to {@code tenant} is what
   *     rejects the row.
   */
  static CheckResult probe(String name, DataSource dataSource, String sql, List<Object> args) {
    long start = System.nanoTime();
    try (Connection con = dataSource.getConnection()) {
      boolean autoCommit = con.getAutoCommit();
      con.setAutoCommit(false);
      try {
        UUID probeTenant = UUID.randomUUID();
        try (Statement set = con.createStatement()) {
          set.execute("SET LOCAL app.tenant = '" + probeTenant + "'");
        }
        try (PreparedStatement ps = con.prepareStatement(sql)) {
          ps.setObject(1, probeTenant);
          for (int i = 0; i < args.size(); i++) {
            ps.setObject(i + 2, args.get(i));
          }
          ps.executeUpdate();
        } catch (SQLException e) {
          if (FK_VIOLATION.equals(e.getSQLState())) {
            return CheckResult.up(
                name, "write_path_verified", Map.of(), DatabaseCheck.elapsedMs(start));
          }
          return CheckResult.down(name, "write_rejected", Map.of(), DatabaseCheck.elapsedMs(start));
        }
        return CheckResult.up(name, "write_path_verified", Map.of(), DatabaseCheck.elapsedMs(start));
      } finally {
        con.rollback();
        con.setAutoCommit(autoCommit);
      }
    } catch (Exception e) {
      return CheckResult.down(name, "unreachable", Map.of(), DatabaseCheck.elapsedMs(start));
    }
  }
}
