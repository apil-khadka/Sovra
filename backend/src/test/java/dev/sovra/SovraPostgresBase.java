package dev.sovra;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import javax.sql.DataSource;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Real-PostgreSQL harness with a JVM singleton container. A Jupiter-managed
 * {@code @Container} field is stopped after each test class and recreated on
 * the next, while Spring reuses the first class's cached context with its
 * stale JDBC URL; the singleton keeps one container, one context, and honest
 * green runs. Ryuk removes the container at JVM exit.
 */
public abstract class SovraPostgresBase {

  static final String APP_ROLE = "sovra_app";
  static final String APP_ROLE_PASSWORD = "sovra-app-test";
  static final String QUARANTINE_ROLE = "sovra_quarantine";
  static final String QUARANTINE_ROLE_PASSWORD = "sovra-quarantine-test";

  static final PostgreSQLContainer POSTGRES =
      new PostgreSQLContainer(DockerImageName.parse("postgres:17.7"))
          .withInitScript("pg-init.sql");

  static {
    POSTGRES.start();
  }

  @DynamicPropertySource
  static void database(DynamicPropertyRegistry registry) {
    registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
    registry.add("spring.datasource.username", POSTGRES::getUsername);
    registry.add("spring.datasource.password", POSTGRES::getPassword);
    registry.add("spring.flyway.user", POSTGRES::getUsername);
    registry.add("spring.flyway.password", POSTGRES::getPassword);
  }

  private static HikariDataSource ownerPool;
  private static HikariDataSource appPool;
  private static HikariDataSource quarantinePool;

  /** Least-privilege connection for RLS/grant assertions. */
  protected static synchronized DataSource appRoleDataSource() {
    if (appPool == null) {
      appPool = roleDataSource(APP_ROLE, APP_ROLE_PASSWORD);
    }
    return appPool;
  }

  /** Isolated-worker connection for containment assertions. */
  protected static synchronized DataSource quarantineRoleDataSource() {
    if (quarantinePool == null) {
      quarantinePool = roleDataSource(QUARANTINE_ROLE, QUARANTINE_ROLE_PASSWORD);
    }
    return quarantinePool;
  }

  /** Owner connection for fixtures and cross-tenant seeding. */
  protected static synchronized DataSource ownerDataSource() {
    if (ownerPool == null) {
      ownerPool = roleDataSource(POSTGRES.getUsername(), POSTGRES.getPassword());
    }
    return ownerPool;
  }

  private static HikariDataSource roleDataSource(String user, String password) {
    HikariConfig config = new HikariConfig();
    config.setJdbcUrl(POSTGRES.getJdbcUrl());
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(2);
    config.setConnectionTimeout(10_000);
    config.setMaxLifetime(300_000);
    config.setLeakDetectionThreshold(2_000);
    return new HikariDataSource(config);
  }
}
