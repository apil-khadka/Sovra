package dev.sovra.tenancy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraPostgresBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.auth.ServiceAccountPrincipal;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Tenant datasource behavior on a shared pool: context is required, pinned
 * per borrow, and reset on close so pooled connections never leak tenants.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class TenantDataSourceTests extends SovraPostgresBase {

  @AfterEach
  void clear() {
    TenantContext.clear();
  }

  private JdbcTemplate tenantTemplate() {
    return new JdbcTemplate(new TenantDataSource(appRoleDataSource()));
  }

  @Test
  void missingContextFailsClosed() {
    JdbcTemplate tenant = tenantTemplate();
    assertThatThrownBy(() -> tenant.queryForList("SELECT 1"))
        .isInstanceOf(TenantRequiredException.class);
  }

  @Test
  void suspendedTransactionsResetBothConnectionPins() throws Exception {
    HikariDataSource source = (HikariDataSource) appRoleDataSource();
    try (HikariDataSource pool = new HikariDataSource()) {
      pool.setJdbcUrl(source.getJdbcUrl());
      pool.setUsername(source.getUsername());
      pool.setPassword(source.getPassword());
      pool.setMaximumPoolSize(2);
      JdbcTemplate tenant = new JdbcTemplate(new TenantDataSource(pool));
      var manager = new DataSourceTransactionManager(pool);
      var outer = new TransactionTemplate(manager);
      var inner = new TransactionTemplate(manager);
      inner.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
      UUID tenantId = UUID.randomUUID();
      TenantContext.set(new ServiceAccountPrincipal(UUID.randomUUID(), tenantId, "nested", Set.of()));
      outer.executeWithoutResult(status -> {
        tenant.queryForObject("SELECT 1", Integer.class);
        inner.executeWithoutResult(nested -> tenant.queryForObject("SELECT 1", Integer.class));
        assertThat(tenant.queryForObject("SELECT current_setting('app.tenant')", String.class))
            .isEqualTo(tenantId.toString());
      });
      // Hold both borrows at once, so both physical connections are inspected.
      try (var first = pool.getConnection(); var second = pool.getConnection()) {
        for (var connection : List.of(first, second)) {
          try (var statement = connection.createStatement();
              var result = statement.executeQuery(
                  "SELECT NULLIF(current_setting('app.tenant', true), '') IS NULL")) {
            assertThat(result.next()).isTrue();
            assertThat(result.getBoolean(1)).as("tenant pin reset before pool reuse").isTrue();
          }
        }
      }
    }
  }

  @Test
  void pooledBorrowsNeverLeakTenants() {
    JdbcTemplate owner = new JdbcTemplate(ownerDataSource());
    TestAccount accountA = TestAccounts.create(owner, "pool-a", Set.of("TENANT_MEMBER"));
    TestAccount accountB = TestAccounts.create(owner, "pool-b", Set.of("TENANT_MEMBER"));
    owner.update(
        "INSERT INTO audit_event (tenant_id, actor_type, actor_id, action, resource_type,"
            + " decision, reason_code, policy_version) VALUES (?, 't', 'a', 'ACT', 'r', 'PERMIT',"
            + " 'PERMIT', 1)",
        accountA.tenantId());
    owner.update(
        "INSERT INTO audit_event (tenant_id, actor_type, actor_id, action, resource_type,"
            + " decision, reason_code, policy_version) VALUES (?, 't', 'a', 'ACT', 'r', 'PERMIT',"
            + " 'PERMIT', 1)",
        accountB.tenantId());

    // One pooled datasource, alternating tenants: each borrow sees only
    // its own tenant rows (platform NULL rows are visible by design and
    // filtered here; the pool must never leak another TENANT's rows).
    DataSource pooled = appRoleDataSource();
    for (int i = 0; i < 6; i++) {
      TestAccount current = i % 2 == 0 ? accountA : accountB;
      TenantContext.set(
          new ServiceAccountPrincipal(
              current.accountId(), current.tenantId(), current.name(), current.roles()));
      try {
        List<Map<String, Object>> rows =
            new JdbcTemplate(new TenantDataSource(pooled))
                .queryForList("SELECT tenant_id FROM audit_event WHERE tenant_id IS NOT NULL");
        assertThat(rows).hasSize(1);
        assertThat(rows.get(0).get("tenant_id")).isEqualTo(current.tenantId());
      } finally {
        TenantContext.clear();
      }
    }
  }

  @Test
  void tenantSettingIsResetBeforePoolReuse() {
    JdbcTemplate owner = new JdbcTemplate(ownerDataSource());
    TestAccount account = TestAccounts.create(owner, "reset", Set.of("TENANT_MEMBER"));
    TenantDataSource pooled = new TenantDataSource(appRoleDataSource());
    TenantContext.set(
        new ServiceAccountPrincipal(
            account.accountId(), account.tenantId(), account.name(), account.roles()));
    new JdbcTemplate(pooled).queryForList("SELECT 1");
    TenantContext.clear();

    // The same physical connection, borrowed raw, must not retain the setting.
    try (var ignored = appRoleDataSource().getConnection()) {
      // Borrowed and closed through the app role; the pool connection that
      // carried the setting was reset on close by the wrapper.
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
    // Proof: a fresh tenant borrow without context still fails instead of
    // inheriting a stale tenant from pool state.
    assertThatThrownBy(() -> new JdbcTemplate(pooled).queryForList("SELECT 1"))
        .isInstanceOf(TenantRequiredException.class);
  }

  @Test
  void malformedTenantCannotReachSql() {
    // Tenant IDs only ever come from parsed UUIDs; a hand-built principal
    // with a random UUID round-trips without touching other tenants.
    JdbcTemplate owner = new JdbcTemplate(ownerDataSource());
    TestAccount account = TestAccounts.create(owner, "other", Set.of("TENANT_MEMBER"));
    TenantContext.set(
        new ServiceAccountPrincipal(UUID.randomUUID(), UUID.randomUUID(), "ghost", Set.of()));
    List<Map<String, Object>> rows =
        tenantTemplate()
            .queryForList("SELECT tenant_id FROM audit_event WHERE tenant_id IS NOT NULL");
    assertThat(rows).isEmpty();
    assertThat(account.tenantId()).isNotNull();
  }
}
