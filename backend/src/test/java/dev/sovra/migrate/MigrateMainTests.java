package dev.sovra.migrate;

import static org.assertj.core.api.Assertions.assertThat;

import com.zaxxer.hikari.HikariDataSource;
import dev.sovra.SovraPostgresBase;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Migration job idempotence (PROD-002): a fresh database migrates
 * from zero to current, and a second run applies nothing. No Spring
 * context — the job is a plain main over raw Flyway.
 */
class MigrateMainTests extends SovraPostgresBase {

  @Test
  void freshDatabaseMigratesThenIdles() {
    JdbcTemplate owner = new JdbcTemplate(ownerDataSource());
    owner.execute("DROP DATABASE IF EXISTS migrate_probe");
    owner.execute("CREATE DATABASE migrate_probe");
    try {
      HikariDataSource hikari = (HikariDataSource) ownerDataSource();
      String base = hikari.getJdbcUrl();
      String url = base.substring(0, base.lastIndexOf('/')) + "/migrate_probe";
      int applied = MigrateMain.migrate(url, hikari.getUsername(), hikari.getPassword());
      assertThat(applied).isGreaterThan(30);
      assertThat(MigrateMain.migrate(url, hikari.getUsername(), hikari.getPassword()))
          .isEqualTo(0);
    } finally {
      owner.execute("DROP DATABASE IF EXISTS migrate_probe");
    }
  }
}
