package dev.sovra;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import javax.sql.DataSource;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Boots the application itself as the least-privilege role (migrations
 * still run as the owner via Flyway credentials), proving the HTTP stack
 * end to end under production-shaped grants. JVM singleton for the same
 * reason as {@link SovraPostgresBase}.
 */
public abstract class SovraAppRoleBase {

  static final PostgreSQLContainer POSTGRES =
      new PostgreSQLContainer(DockerImageName.parse("postgres:17.7"))
          .withInitScript("pg-init.sql");

  static {
    POSTGRES.start();
  }

  @DynamicPropertySource
  static void database(DynamicPropertyRegistry registry) {
    registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
    registry.add("spring.datasource.username", () -> SovraPostgresBase.APP_ROLE);
    registry.add("spring.datasource.password", () -> SovraPostgresBase.APP_ROLE_PASSWORD);
    registry.add("spring.flyway.user", POSTGRES::getUsername);
    registry.add("spring.flyway.password", POSTGRES::getPassword);
  }

  private static HikariDataSource ownerPool;
  private static HikariDataSource quarantinePool;

  /** Isolated-worker connection against this base's own container. */
  protected static synchronized DataSource quarantineRoleDataSource() {
    if (quarantinePool == null) {
      HikariConfig config = new HikariConfig();
      config.setJdbcUrl(POSTGRES.getJdbcUrl());
      config.setUsername(SovraPostgresBase.QUARANTINE_ROLE);
      config.setPassword(SovraPostgresBase.QUARANTINE_ROLE_PASSWORD);
      config.setMaximumPoolSize(2);
      config.setMaxLifetime(300_000);
      quarantinePool = new HikariDataSource(config);
    }
    return quarantinePool;
  }

  /** Owner connection for fixtures (this base owns its own container). */
  protected static synchronized DataSource ownerDataSource() {
    if (ownerPool == null) {
      HikariConfig config = new HikariConfig();
      config.setJdbcUrl(POSTGRES.getJdbcUrl());
      config.setUsername(POSTGRES.getUsername());
      config.setPassword(POSTGRES.getPassword());
      config.setMaximumPoolSize(2);
      config.setMaxLifetime(300_000);
      ownerPool = new HikariDataSource(config);
    }
    return ownerPool;
  }
}
