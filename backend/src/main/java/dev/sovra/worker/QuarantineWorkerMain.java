package dev.sovra.worker;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import dev.sovra.vault.SoftwareVaultKekProvider;
import dev.sovra.vault.VaultKekProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Isolated quarantine worker entrypoint (SOV-017). Own JVM, own
 * database role, no Spring, no HTTP server, no credentials: it polls
 * the admission queue, opens one sealed envelope per transaction,
 * scans it against hard bounds, and writes the verdict. Run one
 * instance per deployment; SKIP LOCKED keeps extra instances safe
 * but redundant.
 */
public final class QuarantineWorkerMain {

  private static final Logger log = LoggerFactory.getLogger(QuarantineWorkerMain.class);

  private QuarantineWorkerMain() {}

  public static void main(String[] args) throws Exception {
    String mode = env("SOVRA_MODE", "demo");
    if (!"demo".equals(mode)) {
      // Production quarantine requires a real KMS KEK (SOV-016 G2):
      // refuse to open sealed bytes under a software fixture.
      log.error("quarantine worker refuses to boot: SOVRA_MODE={} has no KMS KEK", mode);
      System.exit(3);
    }
    String seed = env("SOVRA_VAULT_SEED", "");
    if (seed.isBlank()) {
      log.error("quarantine worker refuses to boot: SOVRA_VAULT_SEED is unset");
      System.exit(3);
    }
    VaultKekProvider kek = new SoftwareVaultKekProvider(seed, true);
    HikariConfig config = new HikariConfig();
    config.setJdbcUrl(env("SOVRA_WORKER_DB_URL", "jdbc:postgresql://sovra-db:5432/sovra"));
    config.setUsername(env("SOVRA_WORKER_DB_USER", "sovra_quarantine"));
    config.setPassword(require("SOVRA_WORKER_DB_PASSWORD"));
    config.setMaximumPoolSize(2);
    config.setMinimumIdle(1);
    config.setConnectionTimeout(5_000);
    config.setMaxLifetime(300_000);
    config.setInitializationFailTimeout(-1);
    long idleMs = Long.parseLong(env("SOVRA_WORKER_IDLE_MS", "500"));
    long errorMs = Long.parseLong(env("SOVRA_WORKER_ERROR_MS", "2000"));
    long bootWaitMs = Long.parseLong(env("SOVRA_WORKER_BOOT_WAIT_MS", "180000"));
    try (HikariDataSource pool = new HikariDataSource(config)) {
      waitForDatabase(pool, bootWaitMs);
      QuarantineWorker worker = new QuarantineWorker(pool, kek);
      log.info("quarantine worker started");
      while (!Thread.currentThread().isInterrupted()) {
        try {
          boolean busy = worker.scanOne();
          Thread.sleep(busy ? 10 : Math.max(50, idleMs));
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        } catch (Exception e) {
          log.warn("quarantine scan failed: {}", String.valueOf(e.getMessage()));
          Thread.sleep(Math.max(100, errorMs));
        }
      }
    }
    log.info("quarantine worker stopped");
  }

  // Migrations run inside app boot, which the worker does not
  // share: wait for the quarantine table to exist instead of
  // crash-looping through the app's Flyway window.
  private static void waitForDatabase(HikariDataSource pool, long bootWaitMs)
      throws InterruptedException {
    long deadline = System.currentTimeMillis() + Math.max(1_000, bootWaitMs);
    while (true) {
      try (java.sql.Connection con = pool.getConnection();
          java.sql.Statement stmt = con.createStatement()) {
        stmt.executeQuery("SELECT 1 FROM quarantine_admission LIMIT 1").close();
        return;
      } catch (Exception e) {
        if (System.currentTimeMillis() >= deadline) {
          log.error("quarantine worker gave up waiting for the database");
          System.exit(3);
        }
        Thread.sleep(2_000);
      }
    }
  }

  private static String env(String name, String fallback) {
    String value = System.getenv(name);
    return value == null ? fallback : value;
  }

  private static String require(String name) {
    String value = System.getenv(name);
    if (value == null || value.isBlank()) {
      log.error("quarantine worker refuses to boot: {} is unset", name);
      System.exit(3);
      throw new IllegalStateException(name + " is unset");
    }
    return value;
  }
}
