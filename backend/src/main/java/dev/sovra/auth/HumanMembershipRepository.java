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

/**
 * Human membership provisioned from OIDC login (SOV-006). Keyed by the
 * stable {@code (issuer, subject)} pair; roles are reloaded from this
 * row on every BFF request, so removal and revocation take effect on
 * the next call. Reads run on the global datasource: membership rows
 * are the pre-tenancy identity record, like service accounts.
 */
@Repository
public class HumanMembershipRepository {

  private final JdbcTemplate global;

  public HumanMembershipRepository(DataSource globalDataSource) {
    this.global = new JdbcTemplate(globalDataSource);
  }

  public record MembershipRow(
      UUID id,
      UUID tenantId,
      String issuer,
      String subject,
      String displayName,
      Set<Role> roles,
      boolean revoked,
      Instant updatedAt) {

    public boolean live() {
      return !revoked;
    }

    public ServiceAccountPrincipal principal() {
      return new ServiceAccountPrincipal(id, tenantId, displayName, roles, issuer, subject);
    }
  }

  /**
   * First-login provision plus role sync; returns the stored row. The
   * tenant pins on first login: a later login carrying another tenant
   * fails closed instead of re-homing the membership. The conditional
   * update closes the concurrent-first-login race the read-then-check
   * in the login service cannot see.
   */
  public MembershipRow upsert(
      UUID tenantId, String issuer, String subject, String displayName, Set<Role> roles) {
    int rows =
        global.update(
            "INSERT INTO human_membership"
                + " (tenant_id, issuer, subject, display_name, roles, updated_at)"
                + " VALUES (?, ?, ?, ?, ?::text[], now())"
                + " ON CONFLICT (issuer, subject) DO UPDATE SET"
                + " display_name = EXCLUDED.display_name,"
                + " roles = EXCLUDED.roles, updated_at = now()"
                + " WHERE human_membership.tenant_id = EXCLUDED.tenant_id",
            tenantId,
            issuer,
            subject,
            displayName,
            roles.stream().map(Role::name).toArray(String[]::new));
    if (rows == 0) {
      throw new HumanTenantConflictException();
    }
    return findBySubject(issuer, subject).orElseThrow();
  }

  public Optional<MembershipRow> findBySubject(String issuer, String subject) {
    List<MembershipRow> rows =
        global.query(
            "SELECT id, tenant_id, issuer, subject, display_name, roles, revoked, updated_at"
                + " FROM human_membership WHERE issuer = ? AND subject = ?",
            this::mapRow,
            issuer,
            subject);
    return rows.stream().findFirst();
  }

  /** Live credential revalidation for the authorization path. */
  public Optional<MembershipRow> findLive(UUID id) {
    List<MembershipRow> rows =
        global.query(
            "SELECT id, tenant_id, issuer, subject, display_name, roles, revoked, updated_at"
                + " FROM human_membership WHERE id = ?",
            this::mapRow,
            id);
    return rows.stream().findFirst();
  }

  /**
   * Terminal removal of a human's access. The row stays for audit
   * joins; liveness and every cached grant die with it.
   */
  public void revoke(UUID id) {
    global.update(
        "UPDATE human_membership SET revoked = TRUE, updated_at = now() WHERE id = ?", id);
  }

  private MembershipRow mapRow(ResultSet rs, int row) throws SQLException {
    Array rolesArray = rs.getArray("roles");
    String[] roles = rolesArray == null ? new String[0] : (String[]) rolesArray.getArray();
    // Fail loud on corrupt rows: the V18 CHECK plus login-time
    // mapping make unknown values unreachable in practice.
    Set<Role> parsed = Role.parseAll(roles);
    return new MembershipRow(
        rs.getObject("id", UUID.class),
        rs.getObject("tenant_id", UUID.class),
        rs.getString("issuer"),
        rs.getString("subject"),
        rs.getString("display_name"),
        parsed,
        rs.getBoolean("revoked"),
        rs.getTimestamp("updated_at").toInstant());
  }
}
