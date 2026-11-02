package dev.sovra.migrate;

import org.flywaydb.core.Flyway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Dedicated migration job (PROD-002). Framework-free by design:
 * plain Flyway over the owner credential, applies pending
 * migrations, prints the count, exits. The serving runtime never
 * runs this path — it sets SOVRA_MIGRATE_ON_BOOT=false and carries
 * no owner credential — and SchemaValidationGuard refuses boot
 * unless this job already brought the schema current.
 *
 * <p>Reads SOVRA_DB_URL, SOVRA_DB_ADMIN_USER,
 * SOVRA_DB_ADMIN_PASSWORD. Exit 0 migrates (possibly zero), exit 2
 * fails the deploy.
 */
public final class MigrateMain {

  private static final Logger log = LoggerFactory.getLogger(MigrateMain.class);

  private MigrateMain() {}

  public static void main(String[] args) {
    String url = require("SOVRA_DB_URL");
    String user = require("SOVRA_DB_ADMIN_USER");
    String password = require("SOVRA_DB_ADMIN_PASSWORD");
    try {
      int applied = migrate(url, user, password);
      log.info("migration job complete: {} migration(s) applied", applied);
    } catch (Exception e) {
      log.error("migration job failed: {}", String.valueOf(e.getMessage()));
      System.exit(2);
    }
  }

  static int migrate(String url, String user, String password) {
    Flyway flyway =
        Flyway.configure()
            .dataSource(url, user, password)
            .locations("classpath:db/migration")
            .validateOnMigrate(true)
            .load();
    return flyway.migrate().migrationsExecuted;
  }

  private static String require(String name) {
    String value = System.getenv(name);
    if (value == null || value.isBlank()) {
      log.error("migration job refuses to run: {} is unset", name);
      System.exit(2);
      throw new IllegalStateException(name + " is unset");
    }
    return value;
  }
}
