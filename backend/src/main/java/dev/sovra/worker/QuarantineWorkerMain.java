package dev.sovra.worker;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import dev.sovra.vault.VaultKekProvider;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Isolated quarantine worker entrypoint (SOV-017, PROD-009). Own JVM,
 * own database role, no Spring, no HTTP server, no credentials: it
 * polls the admission queue, opens one sealed envelope per
 * transaction, scans it against hard bounds, and writes the verdict.
 *
 * <p>Parallelism is bounded: SOVRA_WORKER_CONCURRENCY poll threads
 * (default 4, clamped 1..16) share one QuarantineWorker, each scan
 * holds one pool connection, and the pool is sized concurrency + 1
 * for the sweeper. Claimants never block each other — the claim
 * subselect skips rows locked by a peer (advisory xact lock) — and a
 * periodic sweep requeues scans orphaned by a dead worker, so extra
 * instances and extra threads are safe, not just redundant.
 */
public final class QuarantineWorkerMain {

  private static final Logger log = LoggerFactory.getLogger(QuarantineWorkerMain.class);

  private QuarantineWorkerMain() {}

  public static void main(String[] args) throws Exception {
    VaultKekProvider kek;
    try {
      kek = WorkerKekProviders.fromEnvironment(System.getenv());
    } catch (WorkerKekProviders.WorkerBootException e) {
      log.error("quarantine worker refuses to boot: {}", e.getMessage());
      System.exit(3);
      return;
    }
    int concurrency = Math.min(16, Math.max(1, parseLong(env("SOVRA_WORKER_CONCURRENCY", "4"))));
    long idleMs = Long.parseLong(env("SOVRA_WORKER_IDLE_MS", "500"));
    long errorMs = Long.parseLong(env("SOVRA_WORKER_ERROR_MS", "2000"));
    long bootWaitMs = Long.parseLong(env("SOVRA_WORKER_BOOT_WAIT_MS", "180000"));
    long sweepMs = Long.parseLong(env("SOVRA_WORKER_SWEEP_MS", "60000"));
    Duration lease = Duration.ofMillis(Long.parseLong(env("SOVRA_WORKER_LEASE_MS", "300000")));

    HikariConfig config = new HikariConfig();
    config.setJdbcUrl(env("SOVRA_WORKER_DB_URL", "jdbc:postgresql://sovra-db:5432/sovra"));
    config.setUsername(env("SOVRA_WORKER_DB_USER", "sovra_quarantine"));
    config.setPassword(require("SOVRA_WORKER_DB_PASSWORD"));
    config.setMaximumPoolSize(concurrency + 1);
    config.setMinimumIdle(1);
    config.setConnectionTimeout(5_000);
    config.setMaxLifetime(300_000);
    config.setInitializationFailTimeout(-1);

    HikariDataSource pool = new HikariDataSource(config);
    try {
      waitForDatabase(pool, bootWaitMs);
      String workerId = env("SOVRA_WORKER_ID", defaultWorkerId());
      QuarantineWorker worker = new QuarantineWorker(pool, kek, workerId);
      AtomicBoolean running = new AtomicBoolean(true);
      CountDownLatch stopped = new CountDownLatch(1);

      Thread[] pollers = new Thread[concurrency];
      for (int i = 0; i < concurrency; i++) {
        Thread poller = new Thread(() -> pollLoop(worker, running, idleMs, errorMs),
            "quarantine-scan-" + i);
        pollers[i] = poller;
        poller.start();
      }
      ScheduledExecutorService sweeper = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "quarantine-sweep");
        thread.setDaemon(true);
        return thread;
      });
      sweeper.scheduleWithFixedDelay(
          () -> sweep(worker, lease), sweepMs, sweepMs, TimeUnit.MILLISECONDS);
      // Rescue orphans from a previous crash before the first sweep.
      sweep(worker, lease);
      log.info("quarantine worker started: id={} concurrency={}", workerId, concurrency);

      Runtime.getRuntime().addShutdownHook(new Thread(() -> {
        running.set(false);
        for (Thread poller : pollers) {
          poller.interrupt();
        }
        sweeper.shutdownNow();
        stopped.countDown();
      }));
      stopped.await();
      for (Thread poller : pollers) {
        poller.join(10_000);
      }
      sweeper.awaitTermination(5, TimeUnit.SECONDS);
    } finally {
      pool.close();
    }
    log.info("quarantine worker stopped");
  }

  private static void pollLoop(
      QuarantineWorker worker, AtomicBoolean running, long idleMs, long errorMs) {
    while (running.get() && !Thread.currentThread().isInterrupted()) {
      try {
        boolean busy = worker.scanOne();
        Thread.sleep(busy ? 10 : Math.max(50, idleMs));
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      } catch (Exception e) {
        log.warn("quarantine scan failed: {}", String.valueOf(e.getMessage()));
        try {
          Thread.sleep(Math.max(100, errorMs));
        } catch (InterruptedException interrupted) {
          Thread.currentThread().interrupt();
        }
      }
    }
  }

  private static void sweep(QuarantineWorker worker, Duration lease) {
    try {
      int requeued = worker.requeueStale(lease);
      if (requeued > 0) {
        log.warn("quarantine sweep requeued {} orphaned scan(s)", requeued);
      }
    } catch (Exception e) {
      log.warn("quarantine sweep failed: {}", String.valueOf(e.getMessage()));
    }
  }

  private static String defaultWorkerId() {
    String host;
    try {
      host = java.net.InetAddress.getLocalHost().getHostName();
    } catch (Exception e) {
      host = "unknown";
    }
    return host + "-" + ProcessHandle.current().pid();
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

  private static int parseLong(String value) {
    try {
      return (int) Long.parseLong(value);
    } catch (NumberFormatException e) {
      return 4;
    }
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
