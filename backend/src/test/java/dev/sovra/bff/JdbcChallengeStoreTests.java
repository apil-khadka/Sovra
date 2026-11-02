package dev.sovra.bff;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraPostgresBase;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Atomic challenge consumption in SQL (PROD-003): the conditional
 * {@code DELETE ... RETURNING} lets at most one consumer win, whether
 * the race is threads here or replicas in production. Runs as the
 * least-privilege role to prove the migration grants.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class JdbcChallengeStoreTests extends SovraPostgresBase {

  JdbcChallengeStore store;
  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    // Least-privilege path: the app role must be able to run the
    // whole challenge lifecycle under production-shaped grants.
    store = new JdbcChallengeStore(appRoleDataSource());
    owner = new JdbcTemplate(ownerDataSource());
    owner.update("DELETE FROM holder_unlock_challenge");
  }

  @Test
  void concurrentConsumersBindAtMostOnce() throws Exception {
    UUID member = UUID.randomUUID();
    Instant now = Instant.now();
    assertThat(store.issue(member, "race-challenge", now.plusSeconds(300))).isTrue();

    int racers = 16;
    ExecutorService pool = Executors.newFixedThreadPool(racers);
    try {
      List<Future<Boolean>> futures = new ArrayList<>();
      for (int i = 0; i < racers; i++) {
        Callable<Boolean> race = () -> store.consume(member, "race-challenge", Instant.now());
        futures.add(pool.submit(race));
      }
      int winners = 0;
      for (Future<Boolean> future : futures) {
        if (future.get()) {
          winners++;
        }
      }
      assertThat(winners).isEqualTo(1);
    } finally {
      pool.shutdownNow();
    }
    assertThat(countRows()).isEqualTo(0);
  }

  @Test
  void expiredAndForeignChallengesNeverConsume() {
    UUID member = UUID.randomUUID();
    Instant now = Instant.now();
    store.issue(member, "live", now.plusSeconds(300));
    store.issue(member, "stale", now.minusSeconds(1));
    assertThat(store.consume(member, "stale", now)).isFalse();
    assertThat(store.consume(UUID.randomUUID(), "live", now)).isFalse();
    assertThat(store.consume(member, "missing", now)).isFalse();
    // The live challenge survives the failed attempts above.
    assertThat(store.consume(member, "live", now)).isTrue();
  }

  @Test
  void reapingAndMemberPurgeBehave() {
    UUID member = UUID.randomUUID();
    Instant now = Instant.now();
    store.issue(member, "old", now.minusSeconds(1));
    store.issue(member, "fresh", now.plusSeconds(300));
    store.issue(UUID.randomUUID(), "theirs", now.plusSeconds(300));
    assertThat(store.deleteExpired(now)).isEqualTo(1);
    store.deleteForMember(member);
    assertThat(countRows()).isEqualTo(1);
  }

  @Test
  void duplicateIssueReportsCollision() {
    UUID member = UUID.randomUUID();
    Instant expires = Instant.now().plusSeconds(300);
    assertThat(store.issue(member, "once", expires)).isTrue();
    assertThat(store.issue(member, "once", expires)).isFalse();
  }

  private int countRows() {
    Integer count = owner.queryForObject("SELECT COUNT(*) FROM holder_unlock_challenge", Integer.class);
    return count == null ? 0 : count;
  }
}
