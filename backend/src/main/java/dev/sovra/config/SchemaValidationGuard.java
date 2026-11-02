package dev.sovra.config;

import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * Serve-side schema gate (PROD-002). When in-boot migration is
 * disabled ({@code SOVRA_MIGRATE_ON_BOOT=false}), the dedicated
 * migration job owns DDL and this guard fails boot unless the
 * schema is already current: any pending migration, any checksum
 * drift, or a missing history table refuses to serve. It runs
 * first, before the production scan, on the app's own
 * least-privilege connection — SELECT on the history table only
 * (see V33), never DDL.
 */
@Component
@ConditionalOnProperty(name = "spring.flyway.enabled", havingValue = "false")
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SchemaValidationGuard implements ApplicationRunner {

  private static final Logger log = LoggerFactory.getLogger(SchemaValidationGuard.class);

  private final DataSource appDataSource;

  public SchemaValidationGuard(DataSource appDataSource) {
    this.appDataSource = appDataSource;
  }

  @Override
  public void run(ApplicationArguments args) {
    Flyway flyway =
        Flyway.configure()
            .dataSource(appDataSource)
            .locations("classpath:db/migration")
            .load();
    verifyCurrent(flyway);
    log.info("schema validation passed: no pending migrations, no drift");
  }

  static void verifyCurrent(Flyway flyway) {
    MigrationInfo[] pending;
    try {
      pending = flyway.info().pending();
    } catch (Exception e) {
      fail("schema history is unreadable; the migration job has not prepared this database");
      return;
    }
    if (pending.length > 0) {
      StringBuilder versions = new StringBuilder();
      for (MigrationInfo info : pending) {
        if (versions.length() > 0) {
          versions.append(", ");
        }
        versions.append(info.getVersion());
      }
      fail(pending.length + " pending migration(s) (" + versions + ");"
          + " run the migration job before serving");
    }
    try {
      flyway.validate();
    } catch (Exception e) {
      fail("applied migrations drift from the packaged set: " + e.getMessage());
    }
  }

  private static void fail(String message) {
    throw new IllegalStateException("schema validation refused: " + message);
  }
}
