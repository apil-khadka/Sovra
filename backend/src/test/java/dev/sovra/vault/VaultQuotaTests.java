package dev.sovra.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.audit.AuditService;
import dev.sovra.auth.HumanMembershipRepository;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.auth.ServiceAccountRepository;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.tenancy.TenantContext;
import dev.sovra.tenancy.TenantDataSource;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.List;
import java.util.Set;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Tenant vault-object quota (PROD-010): stores under the cap
 * succeed, the store at the cap is refused with a quota error, and
 * the refusal rolls back without sealing anything.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class VaultQuotaTests extends SovraAppRoleBase {

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
  void storesAtCapAreRefused() {
    TestAccount issuer = TestAccounts.create(owner, "vq-issuer", Set.of("ISSUER_OPS"));
    ServiceAccountPrincipal caller = new ServiceAccountPrincipal(
        issuer.accountId(), issuer.tenantId(), issuer.name(), issuer.roles());
    VaultService capped = new VaultService(authz, audit, accounts, humans,
        new SoftwareVaultKekProvider(vaultSeed, true),
        new JdbcTemplate(new TenantDataSource(dataSource)), clock,
        new dev.sovra.config.DemoProperties(), 2);
    TransactionTemplate enkelt = new TransactionTemplate(transactions);
    for (int i = 0; i < 2; i++) {
      final byte[] content =
          ("quota-bytes-" + i).getBytes(StandardCharsets.UTF_8);
      enkelt.execute(
          ignored -> {
            TenantContext.set(caller);
            try {
              capped.store(caller, "https://issuer.example/q", "", List.of("enrollment-review"),
                  content, null, VaultService.IngestionSource.CALLER);
            } finally {
              TenantContext.clear();
            }
            return null;
          });
    }
    assertThatThrownBy(
            () -> enkelt.execute(
                ignored -> {
                  TenantContext.set(caller);
                  try {
                    capped.store(caller, "https://issuer.example/q", "",
                        List.of("enrollment-review"), "over-quota".getBytes(StandardCharsets.UTF_8),
                        null, VaultService.IngestionSource.CALLER);
                  } finally {
                    TenantContext.clear();
                  }
                  return null;
                }))
        .isInstanceOf(VaultQuotaExceededException.class)
        .hasMessageContaining("quota exhausted");
    assertThat(
            owner.queryForObject(
                "SELECT COUNT(*) FROM vault_object WHERE tenant_id = ?",
                Integer.class,
                issuer.tenantId()))
        .isEqualTo(2);
  }
}
