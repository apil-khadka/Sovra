package dev.sovra.trust;

import java.util.Optional;

/**
 * Versioned trust snapshot source (SOV-004 section 3). Returns the
 * currently active snapshot — issuers, keys, scopes, epochs — or empty
 * when no snapshot governs. Callers record the snapshot version in
 * every decision they make under it.
 */
public interface TrustSnapshotProvider {

  Optional<TrustService.SnapshotView> current();
}
