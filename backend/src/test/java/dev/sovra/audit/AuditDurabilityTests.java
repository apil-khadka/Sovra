package dev.sovra.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraPostgresBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ReasonCode;
import dev.sovra.authz.ResourceRef;
import dev.sovra.tenancy.TenantContext;
import java.util.Map;
import java.util.Set;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AuditDurabilityTests extends SovraPostgresBase {

  @Autowired DataSource dataSource;

  @Autowired AuditService audit;

  @Autowired PlatformTransactionManager transactions;

  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    owner = new JdbcTemplate(ownerDataSource());
  }

  @AfterEach
  void clear() {
    TenantContext.clear();
  }

  @Test
  void businessWriteAndEvidenceCommitTogether() {
    TestAccount account = TestAccounts.create(owner, "writer", Set.of("TRUST_ADMIN"));
    TenantContext.set(
        new ServiceAccountPrincipal(
            account.accountId(), account.tenantId(), account.name(), account.roles()));
    new TransactionTemplate(transactions)
        .execute(
            status -> {
              new JdbcTemplate(dataSource)
                  .update(
                      "INSERT INTO trust_snapshot (created_by, note) VALUES (?, 'durability')",
                      "durability-probe");
              audit.record(
                  TenantContext.require(),
                  Action.PROPOSE_TRUST_CHANGE,
                  ResourceRef.global("trust-snapshot", "durability"),
                  Decision.permit(1),
                  "corr-1",
                  Map.of("proposal", "p1"));
              return null;
            });
    Map<String, Object> row = TestAccounts.auditRow(owner, "PROPOSE_TRUST_CHANGE");
    assertThat(row.get("decision")).isEqualTo("PERMIT");
    assertThat(row.get("reason_code")).isEqualTo("PERMIT");
    // Global resource: platform evidence, owned by no tenant.
    assertThat(row.get("tenant_id")).isNull();
    assertThat(row.get("correlation_id")).isEqualTo("corr-1");
    assertThat(row.get("detail").toString()).contains("p1");
  }

  @Test
  void failedEvidenceRollsBackTheBusinessWrite() {
    TenantContext.clear();
    ServiceAccountPrincipal orphan =
        new ServiceAccountPrincipal(
            java.util.UUID.randomUUID(), java.util.UUID.randomUUID(), "orphan", Set.of());
    assertThatThrownBy(
            () ->
                new TransactionTemplate(transactions)
                    .execute(
                        status -> {
                          new JdbcTemplate(dataSource)
                              .update(
                                  "INSERT INTO trust_snapshot (created_by, note)"
                                      + " VALUES ('rollback-probe', 'x')");
                          audit.record(
                              orphan,
                              Action.READ_AUDIT,
                              ResourceRef.global("audit", "events"),
                              Decision.permit(1),
                              "",
                              Map.of());
                          return null;
                        }))
        .isInstanceOf(dev.sovra.tenancy.TenantRequiredException.class);
    Integer count =
        owner.queryForObject(
            "SELECT COUNT(*) FROM trust_snapshot WHERE created_by = 'rollback-probe'",
            Integer.class);
    assertThat(count).isZero();
  }

  @Test
  void denialsAreRecordedWithReasons() {
    TestAccount account = TestAccounts.create(owner, "denied", Set.of("TENANT_MEMBER"));
    TenantContext.set(
        new ServiceAccountPrincipal(
            account.accountId(), account.tenantId(), account.name(), account.roles()));
    audit.recordDenial(
        TenantContext.require(),
        Action.APPROVE_TRUST_CHANGE,
        ResourceRef.global("trust-proposal", "p9"),
        ReasonCode.MISSING_ROLE,
        3);
    Map<String, Object> row = TestAccounts.auditRow(owner, "APPROVE_TRUST_CHANGE");
    assertThat(row.get("decision")).isEqualTo("DENY");
    assertThat(row.get("reason_code")).isEqualTo("MISSING_ROLE");
    assertThat(row.get("policy_version")).isEqualTo(3L);
  }
}
