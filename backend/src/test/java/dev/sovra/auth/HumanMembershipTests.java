package dev.sovra.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraPostgresBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.auth.HumanMembershipRepository.MembershipRow;
import dev.sovra.authz.Role;
import java.util.Set;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Human membership tenant pinning: the first login pins the tenant,
 * re-login in the same tenant syncs, and a login carrying another
 * tenant fails closed instead of re-homing the row.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class HumanMembershipTests extends SovraPostgresBase {

  @Autowired DataSource dataSource;

  @Autowired HumanMembershipRepository memberships;

  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    owner = new JdbcTemplate(ownerDataSource());
  }

  @Test
  void sameTenantReloginSyncs() {
    TestAccount anchor = TestAccounts.create(owner, "hm-anchor", Set.of("TENANT_MEMBER"));
    MembershipRow first =
        memberships.upsert(
            anchor.tenantId(), "https://op.example/hm", "sync-1", "Sync One",
            Set.of(Role.TENANT_MEMBER));
    MembershipRow second =
        memberships.upsert(
            anchor.tenantId(), "https://op.example/hm", "sync-1", "Sync Renamed",
            Set.of(Role.TENANT_MEMBER, Role.TRUST_ADMIN));
    assertThat(second.id()).isEqualTo(first.id());
    assertThat(second.displayName()).isEqualTo("Sync Renamed");
    assertThat(second.roles()).containsExactlyInAnyOrder(Role.TENANT_MEMBER, Role.TRUST_ADMIN);
    assertThat(second.principal().subject()).isEqualTo("sync-1");
  }

  @Test
  void otherTenantLoginFailsClosed() {
    TestAccount first = TestAccounts.create(owner, "hm-first", Set.of("TENANT_MEMBER"));
    TestAccount second = TestAccounts.create(owner, "hm-second", Set.of("TENANT_MEMBER"));
    memberships.upsert(
        first.tenantId(), "https://op.example/hm", "pinned-1", "Pinned One",
        Set.of(Role.TENANT_MEMBER));
    assertThatThrownBy(
            () ->
                memberships.upsert(
                    second.tenantId(), "https://op.example/hm", "pinned-1", "Pinned One",
                    Set.of(Role.TENANT_MEMBER)))
        .isInstanceOf(HumanTenantConflictException.class);
    MembershipRow stored =
        memberships.findBySubject("https://op.example/hm", "pinned-1").orElseThrow();
    assertThat(stored.tenantId()).isEqualTo(first.tenantId());
  }
}
