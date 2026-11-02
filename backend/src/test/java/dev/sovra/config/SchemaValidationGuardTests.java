package dev.sovra.config;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import dev.sovra.SovraPostgresBase;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Serve-side schema gate (PROD-002): with in-boot migration
 * disabled the guard passes on a current schema over the
 * least-privilege role, and refuses a database the migration job
 * never prepared.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class SchemaValidationGuardTests extends SovraPostgresBase {

  @Test
  void passesOnMigratedSchemaAsAppRole() {
    // The shared container is fully migrated by context boot; the
    // guard's SELECT-only history read must succeed as sovra_app.
    Flyway flyway =
        Flyway.configure()
            .dataSource(appRoleDataSource())
            .locations("classpath:db/migration")
            .load();
    SchemaValidationGuard.verifyCurrent(flyway);
  }

  @Test
  void refusesDatabaseTheMigrationJobNeverPrepared() {
    JdbcTemplate owner = new JdbcTemplate(ownerDataSource());
    owner.execute("DROP DATABASE IF EXISTS guard_probe");
    owner.execute("CREATE DATABASE guard_probe");
    com.zaxxer.hikari.HikariDataSource hikari =
        (com.zaxxer.hikari.HikariDataSource) ownerDataSource();
    String base = hikari.getJdbcUrl();
    String probeUrl = base.substring(0, base.lastIndexOf('/')) + "/guard_probe";
    HikariConfig config = new HikariConfig();
    config.setJdbcUrl(probeUrl);
    config.setUsername(hikari.getUsername());
    config.setPassword(hikari.getPassword());
    config.setMaximumPoolSize(1);
    try (HikariDataSource probe = new HikariDataSource(config)) {
      Flyway flyway =
          Flyway.configure().dataSource(probe).locations("classpath:db/migration").load();
      // Either the history is missing (unreadable) or every
      // migration shows pending: both fail closed with the same
      // remediation — run the migration job.
      assertThatThrownBy(() -> SchemaValidationGuard.verifyCurrent(flyway))
          .isInstanceOf(IllegalStateException.class)
          .hasMessageContaining("migration job");
    } finally {
      owner.execute("DROP DATABASE IF EXISTS guard_probe");
    }
  }
}
