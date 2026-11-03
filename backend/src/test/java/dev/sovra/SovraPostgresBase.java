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
      // Single-threaded assertions plus one held connection (see
      // LeastPrivilegeTests: 1 held + 1 borrowed); 3 leaves margin.
      appPool = roleDataSource(APP_ROLE, APP_ROLE_PASSWORD, 3, "sovra-app-test");
    }
    return appPool;
  }

  /** Isolated-worker connection for containment assertions. */
  protected static synchronized DataSource quarantineRoleDataSource() {
    if (quarantinePool == null) {
      // PROD-009: the parallel claim test holds four worker-role
      // connections at once; 5 keeps that burst plus margin.
      quarantinePool =
          roleDataSource(QUARANTINE_ROLE, QUARANTINE_ROLE_PASSWORD, 5, "sovra-quarantine-test");
    }
    return quarantinePool;
  }

  /** Owner connection for fixtures and cross-tenant seeding. */
  protected static synchronized DataSource ownerDataSource() {
    if (ownerPool == null) {
      ownerPool =
          roleDataSource(POSTGRES.getUsername(), POSTGRES.getPassword(), 3, "sovra-owner-test");
    }
    return ownerPool;
  }

  private static HikariDataSource roleDataSource(
      String user, String password, int maxPoolSize, String poolName) {
    HikariConfig config = new HikariConfig();
    config.setJdbcUrl(POSTGRES.getJdbcUrl());
    config.setUsername(user);
    config.setPassword(password);
    // Test-only bounds: the singleton container caps at 100
    // connections shared with every cached Spring context. One warm
    // idle connection per static pool; bursts grow to the ceiling
    // and drain after 30s idle. The default minimumIdle (= max)
    // would pin 8 idle per pool even when no test runs.
    config.setMaximumPoolSize(maxPoolSize);
    config.setMinimumIdle(1);
    config.setIdleTimeout(30_000);
    config.setPoolName(poolName);
    config.setConnectionTimeout(10_000);
    config.setMaxLifetime(300_000);
    config.setLeakDetectionThreshold(2_000);
    return new HikariDataSource(config);
  }
}
