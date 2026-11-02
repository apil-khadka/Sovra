package dev.sovra.tenancy;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.audit.AuditService;
import dev.sovra.auth.HumanMembershipRepository;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.auth.ServiceAccountRepository;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.vault.SoftwareVaultKekProvider;
import dev.sovra.vault.VaultService;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Mixed-tenant isolation under concurrent lifecycle churn
 * (PROD-010): two tenants seal objects concurrently; each tenant
 * ends with exactly its own objects, versions, and audit rows —
 * no cross-tenant write, no lost row, no RLS mixup under thread
 * churn.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class TenantChurnTests extends SovraAppRoleBase {

  @Autowired DataSource dataSource;

  @Autowired AuthorizationService authz;

  @Autowired AuditService audit;

  @Autowired ServiceAccountRepository accounts;

  @Autowired HumanMembershipRepository humans;

  @Autowired Clock clock;

  @Autowired org.springframework.transaction.PlatformTransactionManager transactions;

  @Value("${sovra.vault.seed}")
  String vaultSeed;

  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    owner = new JdbcTemplate(ownerDataSource());
  }

  @Test
  void concurrentTenantsStayPartitioned() throws Exception {
    TestAccount alpha = TestAccounts.create(owner, "churn-alpha", Set.of("ISSUER_OPS"));
    TestAccount beta = TestAccounts.create(owner, "churn-beta", Set.of("ISSUER_OPS"));
    int perTenant = 20;
    ExecutorService pool = Executors.newFixedThreadPool(8);
    try {
      List<Future<?>> futures = new ArrayList<>();
      for (int i = 0; i < perTenant; i++) {
        futures.add(pool.submit(storeTask(alpha, i)));
        futures.add(pool.submit(storeTask(beta, i)));
      }
      for (Future<?> future : futures) {
        future.get();
      }
    } finally {
      pool.shutdownNow();
    }
    assertThat(objects(alpha)).isEqualTo(perTenant);
    assertThat(objects(beta)).isEqualTo(perTenant);
    assertThat(versions(alpha)).isEqualTo(perTenant);
    assertThat(versions(beta)).isEqualTo(perTenant);
    // Audit partitions exactly too: one VAULT_STORE per object.
    assertThat(
            owner.queryForObject(
                "SELECT COUNT(*) FROM audit_event WHERE tenant_id = ? AND action = 'VAULT_STORE_OBJECT'"
                    + " AND actor_id = ?",
                Integer.class,
                alpha.tenantId(),
                alpha.accountId().toString()))
        .isEqualTo(perTenant);
    assertThat(
            owner.queryForObject(
                "SELECT COUNT(*) FROM audit_event WHERE tenant_id = ? AND action = 'VAULT_STORE_OBJECT'"
                    + " AND actor_id = ?",
                Integer.class,
                beta.tenantId(),
                beta.accountId().toString()))
        .isEqualTo(perTenant);
  }

  private Runnable storeTask(TestAccount account, int index) {
    return () -> {
      ServiceAccountPrincipal caller = new ServiceAccountPrincipal(
          account.accountId(), account.tenantId(), account.name(), account.roles());
      VaultService vault = new VaultService(authz, audit, accounts, humans,
          new SoftwareVaultKekProvider(vaultSeed, true),
          new JdbcTemplate(new TenantDataSource(dataSource)), clock,
          new dev.sovra.config.DemoProperties(), 0);
      new TransactionTemplate(transactions)
          .execute(
              ignored -> {
                TenantContext.set(caller);
                try {
                  vault.store(caller, "https://issuer.example/churn", "",
                      List.of("enrollment-review"),
                      ("churn-" + account.name() + "-" + index).getBytes(StandardCharsets.UTF_8),
                      null, VaultService.IngestionSource.CALLER);
                } finally {
                  TenantContext.clear();
                }
                return null;
              });
    };
  }

  private int objects(TestAccount account) {
    return owner.queryForObject(
        "SELECT COUNT(*) FROM vault_object WHERE tenant_id = ?", Integer.class,
        account.tenantId());
  }

  private int versions(TestAccount account) {
    return owner.queryForObject(
        "SELECT COUNT(*) FROM vault_object_version WHERE tenant_id = ?", Integer.class,
        account.tenantId());
  }
}
