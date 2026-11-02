package dev.sovra.quarantine;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraPostgresBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.vault.SoftwareVaultKekProvider;
import dev.sovra.worker.QuarantineWorker;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * PROD-009: parallel claims are exactly-once, and crashed scans
 * requeue after their lease. Admissions carry garbage envelopes, so
 * every scan takes the fast seal-failed path — the control under
 * test is the claim/sweep protocol, not the scanner.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class QuarantineWorkerParallelTests extends SovraPostgresBase {

  @Value("${sovra.vault.seed}")
  String vaultSeed;

  JdbcTemplate owner;
  QuarantineWorker worker;
  final List<UUID> mine = new ArrayList<>();

  @BeforeEach
  void setup() throws Exception {
    owner = new JdbcTemplate(ownerDataSource());
    worker =
        new QuarantineWorker(
            quarantineRoleDataSource(),
            new SoftwareVaultKekProvider(vaultSeed, true),
            "parallel-test");
    // The queue is shared across test classes; strays would inflate
    // the exactly-once count, so they drain first.
    while (worker.scanOne()) {
    }
  }

  @AfterEach
  void cleanup() throws Exception {
    while (worker.scanOne()) {
    }
    for (UUID admission : mine) {
      owner.update("DELETE FROM quarantine_admission WHERE id = ?", admission);
    }
    mine.clear();
  }

  @Test
  void parallelDrainClaimsEachAdmissionOnce() throws Exception {
    int admissions = 20;
    for (int i = 0; i < admissions; i++) {
      seedAdmission("QUARANTINED");
    }
    AtomicInteger claimed = new AtomicInteger();
    ExecutorService pool = Executors.newFixedThreadPool(4);
    try {
      List<Future<?>> futures = new ArrayList<>();
      for (int i = 0; i < 4; i++) {
        futures.add(
            pool.submit(
                () -> {
                  try {
                    while (worker.scanOne()) {
                      claimed.incrementAndGet();
                    }
                  } catch (Exception e) {
                    throw new RuntimeException(e);
                  }
                }));
      }
      for (Future<?> future : futures) {
        future.get();
      }
    } finally {
      pool.shutdownNow();
    }
    assertThat(claimed.get()).isEqualTo(admissions);
    for (UUID admission : mine) {
      assertThat(status(admission)).isEqualTo("REJECTED");
      assertThat(
              owner.queryForObject(
                  "SELECT verdict FROM quarantine_admission WHERE id = ?",
                  String.class,
                  admission))
          .startsWith("seal-failed");
      assertThat(
              owner.queryForObject(
                  "SELECT claimed_by FROM quarantine_admission WHERE id = ?",
                  String.class,
                  admission))
          .isEqualTo("parallel-test");
    }
    assertThat(
            owner.queryForObject(
                "SELECT COUNT(*) FROM quarantine_admission"
                    + " WHERE claimed_by = 'parallel-test' AND claimed_at IS NULL",
                Integer.class))
        .isEqualTo(0);
  }

  @Test
  void staleScansRequeueAfterLease() throws Exception {
    UUID stale = seedAdmission("SCANNING");
    owner.update(
        "UPDATE quarantine_admission SET claimed_at = now() - interval '1 hour',"
            + " claimed_by = 'dead-worker' WHERE id = ?",
        stale);
    assertThat(worker.requeueStale(Duration.ofMinutes(5))).isEqualTo(1);
    assertThat(status(stale)).isEqualTo("QUARANTINED");
    assertThat(
            owner.queryForObject(
                "SELECT verdict FROM quarantine_admission WHERE id = ?", String.class, stale))
        .isEqualTo("requeued-after-lease");
    // The rescued row scans normally on the next pass.
    assertThat(worker.scanOne()).isTrue();
    assertThat(status(stale)).isEqualTo("REJECTED");
  }

  @Test
  void freshScansKeepTheirLease() {
    UUID fresh = seedAdmission("SCANNING");
    owner.update(
        "UPDATE quarantine_admission SET claimed_at = now(), claimed_by = 'live-worker'"
            + " WHERE id = ?",
        fresh);
    int requeued = 0;
    try {
      requeued = worker.requeueStale(Duration.ofMinutes(5));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    assertThat(requeued).isEqualTo(0);
    assertThat(status(fresh)).isEqualTo("SCANNING");
    owner.update(
        "UPDATE quarantine_admission SET status = 'QUARANTINED' WHERE id = ?", fresh);
  }

  private String status(UUID admission) {
    return owner.queryForObject(
        "SELECT status FROM quarantine_admission WHERE id = ?", String.class, admission);
  }

  private UUID seedAdmission(String status) {
    TestAccount ops = TestAccounts.create(owner, "quar-par-" + UUID.randomUUID(), Set.of());
    UUID objectId = UUID.randomUUID();
    owner.update(
        "INSERT INTO vault_object (id, tenant_id, issuer_id, created_by)"
            + " VALUES (?, ?, 'https://issuer.example/q', 'seed')",
        objectId, ops.tenantId());
    owner.update(
        "INSERT INTO vault_object_version (object_id, version, tenant_id, issuer_id,"
            + " authorized_purposes, content_sha256, kek_version, wrapped_dek, dek_nonce,"
            + " content_nonce, ciphertext, created_by)"
            + " VALUES (?, 1, ?, 'https://issuer.example/q',"
            + " ARRAY['quarantine-scan'], '\\x00', 1, '\\x00', '\\x00', '\\x00',"
            + " '\\x00', 'seed')",
        objectId, ops.tenantId());
    UUID admission = UUID.randomUUID();
    owner.update(
        "INSERT INTO quarantine_admission (id, tenant_id, vault_object_id, actual_type,"
            + " size_bytes, content_sha256, status, created_by)"
            + " VALUES (?, ?, ?, 'png', 8, '\\x00', ?, 'seed')",
        admission, ops.tenantId(), objectId, status);
    mine.add(admission);
    return admission;
  }
}
