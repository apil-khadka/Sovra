package dev.sovra.auth;

import dev.sovra.authz.Role;
import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/** Service-account lookup on the global (non-tenant) datasource. */
@Repository
public class ServiceAccountRepository {

  private final JdbcTemplate global;

  public ServiceAccountRepository(DataSource globalDataSource) {
    this.global = new JdbcTemplate(globalDataSource);
  }

  /** Finds candidate accounts by token prefix; hash comparison stays in Java. */
  public List<AccountRow> findByPrefix(String prefix) {
    return global.query(
        "SELECT id, tenant_id, name, token_hash, roles, revoked, expires_at"
            + " FROM service_account WHERE token_prefix = ?",
        this::mapRow,
        prefix);
  }

  /** Live credential revalidation for the authorization path. */
  public Optional<AccountRow> findLive(UUID id) {
    List<AccountRow> rows =
        global.query(
            "SELECT id, tenant_id, name, token_hash, roles, revoked, expires_at"
                + " FROM service_account WHERE id = ?",
            this::mapRow,
            id);
    return rows.stream().findFirst();
  }

  private AccountRow mapRow(ResultSet rs, int row) throws SQLException {
    Array rolesArray = rs.getArray("roles");
    String[] roles = rolesArray == null ? new String[0] : (String[]) rolesArray.getArray();
    // Fail loud on corrupt rows: the V18 CHECK plus creation-time
    // validation make unknown values unreachable in practice.
    Set<Role> parsed = Role.parseAll(roles);
    return new AccountRow(
        rs.getObject("id", UUID.class),
        rs.getObject("tenant_id", UUID.class),
        rs.getString("name"),
        rs.getBytes("token_hash"),
        parsed,
        rs.getBoolean("revoked"),
        rs.getTimestamp("expires_at") == null
            ? null
            : rs.getTimestamp("expires_at").toInstant());
  }

  public record AccountRow(
      UUID id,
      UUID tenantId,
      String name,
      byte[] tokenHash,
      java.util.Set<Role> roles,
      boolean revoked,
      Instant expiresAt) {

    public boolean live(Instant now) {
      if (revoked) {
        return false;
      }
      return expiresAt == null || expiresAt.isAfter(now);
    }

    public ServiceAccountPrincipal principal() {
      return new ServiceAccountPrincipal(id, tenantId, name, roles);
    }
  }
}
