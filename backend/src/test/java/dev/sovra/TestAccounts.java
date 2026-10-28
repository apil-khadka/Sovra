package dev.sovra;

import dev.sovra.auth.TokenHasher;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.JdbcTemplate;

/** Fixture factory for tenants and service accounts with random tokens. */
public final class TestAccounts {

  private TestAccounts() {}

  public record TestAccount(
      UUID tenantId, String tenantSlug, UUID accountId, String name, String token, Set<String> roles) {

    public java.util.function.Consumer<HttpHeaders> headers() {
      return headers -> headers.setBearerAuth(token);
    }
  }

  public static TestAccount create(JdbcTemplate owner, String name, Set<String> roles) {
    String slug = "t-" + UUID.randomUUID().toString().substring(0, 8);
    UUID tenantId =
        owner.queryForObject(
            "INSERT INTO tenant (slug, display_name) VALUES (?, ?) RETURNING id",
            UUID.class,
            slug,
            "Test " + slug);
    String token = TokenHasher.generate();
    UUID accountId =
        owner.queryForObject(
            "INSERT INTO service_account (tenant_id, name, token_prefix, token_hash, roles)"
                + " VALUES (?, ?, ?, ?, ?) RETURNING id",
            UUID.class,
            tenantId,
            name,
            TokenHasher.prefix(token),
            TokenHasher.hash(token),
            roles.toArray(new String[0]));
    return new TestAccount(tenantId, slug, accountId, name, token, roles);
  }

  public static void revoke(JdbcTemplate owner, UUID accountId) {
    owner.update("UPDATE service_account SET revoked = TRUE WHERE id = ?", accountId);
  }

  /** Raw audit-row text for canary assertions (owner bypasses RLS). */
  public static String allAuditText(JdbcTemplate owner) {
    return String.join(
        "\n",
        owner.query(
            "SELECT audit_event::text FROM audit_event", (rs, row) -> rs.getString(1)));
  }

  public static int auditCount(JdbcTemplate owner) {
    Integer count = owner.queryForObject("SELECT COUNT(*) FROM audit_event", Integer.class);
    return count == null ? 0 : count;
  }

  public static Map<String, Object> auditRow(JdbcTemplate owner, String action) {
    return owner.queryForMap(
        "SELECT * FROM audit_event WHERE action = ? ORDER BY occurred_at DESC LIMIT 1", action);
  }
}
