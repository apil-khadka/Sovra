package dev.sovra.trust;

import dev.sovra.authz.EmergencyFlagService;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Bounded trust-snapshot cache (SOV-004 section 5, PROD-008):
 * 60-minute max age, single live entry, version-checked on every
 * read. A live emergency flag bypasses the cache.
 *
 * <p>Concurrency shape: readers are lock-free. Each read takes one
 * cheap indexed version check plus a volatile lookup; only a
 * version bump or TTL expiry takes the writer lock, and the
 * double-check inside means concurrent refreshers load once. The
 * per-read version check is the revocation signal — a new snapshot
 * (key rotation, issuer removal) is visible on the very next read,
 * never after a TTL. G1 refreshes lazily on access after expiry;
 * background refresh is a G2 optimization that does not change the
 * max-age bound enforced here.
 */
@Service
public class CachingTrustSnapshotProvider implements TrustSnapshotProvider {

  static final Duration MAX_AGE = Duration.ofMinutes(60);

  private final TrustService trust;
  private final EmergencyFlagService emergency;
  private final JdbcTemplate global;
  private final Clock clock;
  private final Object writeLock = new Object();

  private volatile Cached current;

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
  public Optional<TrustService.SnapshotView> current() {
    if (emergency.enabled()) {
      return fresh();
    }
    // Outside any lock: the revocation signal must never wait
    // behind another reader's snapshot load.
    Long version =
        global.queryForObject(
            "SELECT MAX(snapshot_version) FROM trust_snapshot_activation", Long.class);
    if (version == null) {
      return Optional.empty();
    }
    Cached snap = current;
    if (usable(snap, version)) {
      return Optional.of(snap.view);
    }
    synchronized (writeLock) {
      snap = current;
      if (usable(snap, version)) {
        return Optional.of(snap.view);
      }
      Optional<TrustService.SnapshotView> view = fresh();
      view.ifPresent(v -> current = new Cached(v, clock.instant()));
      return view;
    }
  }

  private boolean usable(Cached snap, long version) {
    return snap != null
        && snap.view.version() == version
        && snap.fetchedAt.plus(MAX_AGE).isAfter(clock.instant());
  }

  private Optional<TrustService.SnapshotView> fresh() {
    return trust.currentSnapshot();
  }

  private record Cached(TrustService.SnapshotView view, Instant fetchedAt) {}
}
