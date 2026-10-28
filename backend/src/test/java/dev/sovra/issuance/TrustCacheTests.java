package dev.sovra.issuance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import dev.sovra.SovraPostgresBase;
import dev.sovra.authz.EmergencyFlagService;
import dev.sovra.trust.TrustService;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.UUID;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Trust-snapshot cache bounds: version-keyed, 60-minute max age, 4
 * entries, emergency bypass. The mocked TrustService always answers for
 * the live activation version, so invocation counts prove hits/misses.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class TrustCacheTests extends SovraPostgresBase {

  JdbcTemplate owner;
  long baseVersion;

  @BeforeEach
  void setup() {
    owner = new JdbcTemplate(ownerDataSource());
    baseVersion = currentMax();
    owner.update("UPDATE emergency_flag SET enabled = FALSE WHERE id = 1");
  }

  @AfterEach
  void restore() {
    // Newer versions than the setup tip are this class's fixtures or
    // other classes' unactivated leftovers (the shared container); all
    // of them go, children before parents. Activated versions carry no
    // fixture issuer rows, so the seal never fires here.
    owner.update(
        "DELETE FROM trust_proposal_decision WHERE proposal_id IN"
            + " (SELECT id FROM trust_change_proposal WHERE snapshot_version > ?)",
        baseVersion);
    owner.update(
        "DELETE FROM trust_change_proposal WHERE snapshot_version > ?", baseVersion);
    owner.update("DELETE FROM issuer_record WHERE snapshot_version > ?", baseVersion);
    owner.update("DELETE FROM rp_policy WHERE snapshot_version > ?", baseVersion);
    owner.update("DELETE FROM trust_snapshot_activation WHERE snapshot_version > ?",
        baseVersion);
    owner.update("DELETE FROM trust_snapshot WHERE version > ?", baseVersion);
    owner.update("UPDATE emergency_flag SET enabled = FALSE WHERE id = 1");
  }

  private long activateFresh() {
    Long version =
        owner.queryForObject(
            "INSERT INTO trust_snapshot (created_by, note) VALUES ('cache-test', '')"
                + " RETURNING version",
            Long.class);
    // The seal (V13) admits activation only for approved versions, so
    // the fixture carries a proposal plus decision first.
    UUID proposal =
        owner.queryForObject(
            "INSERT INTO trust_change_proposal (snapshot_version, proposed_by)"
                + " VALUES (?, 'cache-maker') RETURNING id",
            UUID.class,
            version);
    owner.update(
        "INSERT INTO trust_proposal_decision (proposal_id, approved_by) VALUES (?, 'cache-checker')",
        proposal);
    owner.update(
        "INSERT INTO trust_snapshot_activation (snapshot_version, activated_by)"
            + " VALUES (?, 'cache-test')",
        version);
    return version;
  }

  private long currentMax() {
    Long max = owner.queryForObject(
        "SELECT MAX(snapshot_version) FROM trust_snapshot_activation", Long.class);
    return max == null ? 0 : max;
  }

  private TrustService answeringMock() {
    TrustService mock = mock(TrustService.class);
    when(mock.currentSnapshot())
        .thenAnswer(
            invocation ->
                Optional.of(new TrustService.SnapshotView(currentMax(), List.of(), List.of())));
    return mock;
  }

  private CachingTrustSnapshotProvider provider(TrustService trust, Clock clock) {
    return new CachingTrustSnapshotProvider(
        trust, new EmergencyFlagService(ownerDataSource(), clock), ownerDataSource(), clock);
  }

  @Test
  void versionBumpInvalidatesTheCache() {
    TrustService mock = answeringMock();
    CachingTrustSnapshotProvider provider =
        provider(mock, Clock.fixed(Instant.now(), ZoneId.of("UTC")));
    assertThat(provider.current()).isPresent();
    assertThat(provider.current().get().version()).isEqualTo(baseVersion);
    verify(mock, times(1)).currentSnapshot();

    long next = activateFresh();
    assertThat(provider.current().get().version()).isEqualTo(next);
    verify(mock, times(2)).currentSnapshot();
  }

  @Test
  void entriesExpireAfterSixtyMinutes() {
    MutableClock clock = new MutableClock(Instant.now());
    TrustService mock = answeringMock();
    CachingTrustSnapshotProvider provider = provider(mock, clock);
    provider.current();
    verify(mock, times(1)).currentSnapshot();

    clock.advance(Duration.ofMinutes(59));
    provider.current();
    verify(mock, times(1)).currentSnapshot();

    clock.advance(Duration.ofMinutes(2));
    provider.current();
    verify(mock, times(2)).currentSnapshot();
  }

  @Test
  void fourthEntryEvictsTheEldest() {
    TrustService mock = answeringMock();
    CachingTrustSnapshotProvider provider =
        provider(mock, Clock.fixed(Instant.now(), ZoneId.of("UTC")));
    // Load five distinct versions; the cache holds four.
    provider.current();
    for (int i = 0; i < 4; i++) {
      long version = activateFresh();
      assertThat(provider.current().get().version()).isEqualTo(version);
    }
    verify(mock, times(5)).currentSnapshot();

    // Back to the first version: evicted means a reload, not a hit.
    owner.update(
        "DELETE FROM trust_proposal_decision WHERE proposal_id IN"
            + " (SELECT id FROM trust_change_proposal WHERE snapshot_version > ?)",
        baseVersion);
    owner.update(
        "DELETE FROM trust_change_proposal WHERE snapshot_version > ?", baseVersion);
    owner.update("DELETE FROM issuer_record WHERE snapshot_version > ?", baseVersion);
    owner.update("DELETE FROM rp_policy WHERE snapshot_version > ?", baseVersion);
    owner.update("DELETE FROM trust_snapshot_activation WHERE snapshot_version > ?",
        baseVersion);
    owner.update("DELETE FROM trust_snapshot WHERE version > ?", baseVersion);
    assertThat(provider.current().get().version()).isEqualTo(baseVersion);
    verify(mock, times(6)).currentSnapshot();
  }

  @Test
  void emergencyFlagBypassesTheCache() {
    owner.update("UPDATE emergency_flag SET enabled = TRUE WHERE id = 1");
    TrustService mock = answeringMock();
    CachingTrustSnapshotProvider provider =
        provider(mock, Clock.fixed(Instant.now(), ZoneId.of("UTC")));
    provider.current();
    provider.current();
    verify(mock, times(2)).currentSnapshot();
  }

  static final class MutableClock extends Clock {
    private final AtomicReference<Instant> now;

    MutableClock(Instant start) {
      this.now = new AtomicReference<>(start);
    }

    void advance(Duration duration) {
      now.updateAndGet(current -> current.plus(duration));
    }

    @Override
    public ZoneId getZone() {
      return ZoneId.of("UTC");
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now.get();
    }
  }
}
