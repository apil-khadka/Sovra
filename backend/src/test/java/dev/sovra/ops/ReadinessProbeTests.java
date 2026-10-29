package dev.sovra.ops;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.authz.EmergencyFlagService;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;
import tools.jackson.databind.ObjectMapper;

/**
 * Readiness probes against real PostgreSQL as the least-privilege role:
 * every check tests its actual dependency, probes persist nothing, and
 * dead dependencies report DOWN with fixed codes (never driver text).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ReadinessProbeTests extends SovraAppRoleBase {

  @Autowired TrustService trust;

  @Autowired ObjectMapper mapper;

  @Autowired DataSource dataSource;

  @Autowired FlowReadinessService readiness;

  JdbcTemplate owner;

  @BeforeEach
  void setup() throws Exception {
    owner = new JdbcTemplate(ownerDataSource());
    IssuanceFixtures.ensureSyntheticIssuer(owner, trust, mapper);
    owner.update(
        "INSERT INTO issuer_signing_key (issuer_id, key_id, key_version, public_key_jwk, status)"
            + " VALUES (?, 'probe-key', 1, '{}'::jsonb, 'ACTIVE') ON CONFLICT DO NOTHING",
        IssuanceFixtures.ISSUER_ID);
  }

  private static DataSource deadDataSource() {
    SimpleDriverDataSource dead = new SimpleDriverDataSource();
    dead.setDriverClass(org.postgresql.Driver.class);
    dead.setUrl("jdbc:postgresql://127.0.0.1:1/nonexistent");
    return dead;
  }

  @Test
  void everyCheckIsUpOnASeededDatabase() {
    FlowReadinessService.ReadinessReport report = readiness.report();
    assertThat(report.status()).isEqualTo("READY");
    assertThat(report.checks()).hasSize(7);
    assertThat(report.checks())
        .allSatisfy(
            result -> {
              assertThat(result.status()).isEqualTo(CheckStatus.UP);
              assertThat(result.durationMs()).isGreaterThanOrEqualTo(0);
            });
    assertThat(report.checks().stream().map(CheckResult::name))
        .containsExactlyInAnyOrder(
            "database",
            "migrations",
            "trust_freshness",
            "authorization",
            "audit_durability",
            "replay_persistence",
            "key_availability");
  }

  @Test
  void probesPersistNothing() {
    int auditBefore = TestCounts.count(owner, "audit_event");
    int decisionsBefore = TestCounts.count(owner, "verification_decision");

    readiness.report();

    assertThat(TestCounts.count(owner, "audit_event")).isEqualTo(auditBefore);
    assertThat(TestCounts.count(owner, "verification_decision")).isEqualTo(decisionsBefore);
  }

  @Test
  void deadDependenciesReportDownWithFixedCodes() {
    DataSource dead = deadDataSource();

    assertThat(new DatabaseCheck(dead).check().status()).isEqualTo(CheckStatus.DOWN);
    assertThat(new MigrationCheck(dead).check().status()).isEqualTo(CheckStatus.DOWN);
    assertThat(new TrustFreshnessCheck(dead, java.time.Clock.systemUTC()).check().status())
        .isEqualTo(CheckStatus.DOWN);
    assertThat(new AuditDurabilityCheck(dead).check().status()).isEqualTo(CheckStatus.DOWN);
    assertThat(new ReplayPersistenceCheck(dead).check().status()).isEqualTo(CheckStatus.DOWN);
    assertThat(new KeyAvailabilityCheck(dead).check().status()).isEqualTo(CheckStatus.DOWN);

    // Fixed codes only: no driver text, SQL, or hostnames escape.
    CheckResult down = new DatabaseCheck(dead).check();
    assertThat(down.code()).isEqualTo("unreachable");
    assertThat(down.detail()).isEmpty();
  }

  @Test
  void emergencyFreezeDegradesAuthorizationReadiness() {
    EmergencyFlagService frozen = Mockito.mock(EmergencyFlagService.class);
    when(frozen.enabled()).thenReturn(true);

    CheckResult result = new AuthorizationCheck(dataSource, frozen).check();

    assertThat(result.status()).isEqualTo(CheckStatus.DEGRADED);
    assertThat(result.code()).isEqualTo("emergency_freeze");
    assertThat(result.detail()).containsEntry("frozen", true);
  }

  static final class TestCounts {
    private TestCounts() {}

    static int count(JdbcTemplate owner, String table) {
      Integer count = owner.queryForObject("SELECT COUNT(*) FROM " + table, Integer.class);
      return count == null ? 0 : count;
    }
  }
}
