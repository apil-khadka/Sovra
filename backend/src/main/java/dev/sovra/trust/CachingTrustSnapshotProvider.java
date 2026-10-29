package dev.sovra.trust;

import dev.sovra.authz.EmergencyFlagService;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Bounded trust-snapshot cache (SOV-004 section 5): 60-minute max age, at
 * most 4 snapshots, keyed by version so a version bump invalidates the
 * class. A live emergency flag bypasses the cache. G1 refreshes lazily
 * on access after TTL expiry; background refresh is a G2 optimization
 * that does not change the max-age bound enforced here.
 */
@Service
public class CachingTrustSnapshotProvider implements TrustSnapshotProvider {

  static final Duration MAX_AGE = Duration.ofMinutes(60);
  static final int MAX_ENTRIES = 4;

  private final TrustService trust;
  private final EmergencyFlagService emergency;
  private final JdbcTemplate global;
  private final Clock clock;
  private final Map<Long, Cached> cache =
      new LinkedHashMap<>(MAX_ENTRIES, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Long, Cached> eldest) {
          return size() > MAX_ENTRIES;
        }
      };

  public CachingTrustSnapshotProvider(
      TrustService trust,
      EmergencyFlagService emergency,
      DataSource globalDataSource,
      Clock clock) {
    this.trust = trust;
    this.emergency = emergency;
    this.global = new JdbcTemplate(globalDataSource);
    this.clock = clock;
  }

  @Override
  public synchronized Optional<TrustService.SnapshotView> current() {
    if (emergency.enabled()) {
      return fresh();
    }
    Long version =
        global.queryForObject(
            "SELECT MAX(snapshot_version) FROM trust_snapshot_activation", Long.class);
    if (version == null) {
      return Optional.empty();
    }
    Cached cached = cache.get(version);
    if (cached != null && cached.fetchedAt.plus(MAX_AGE).isAfter(clock.instant())) {
      return Optional.of(cached.view);
    }
    Optional<TrustService.SnapshotView> view = fresh();
    view.ifPresent(v -> cache.put(v.version(), new Cached(v, clock.instant())));
    return view;
  }

  private Optional<TrustService.SnapshotView> fresh() {
    return trust.currentSnapshot();
  }

  private record Cached(TrustService.SnapshotView view, Instant fetchedAt) {}
}
