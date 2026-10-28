package dev.sovra.authz;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Bounded TTL cache for authorization decisions (SOV-004: 60 seconds,
 * 50,000 entries, grants and denies). The key includes the policy version,
 * so a version bump invalidates every entry. Clearing is always safe:
 * it only costs a recomputation.
 */
public class PermissionCache {

  static final Duration TTL = Duration.ofSeconds(60);
  static final int MAX_ENTRIES = 50_000;

  private final Clock clock;
  private final Map<Key, Entry> entries = new ConcurrentHashMap<>();

  public PermissionCache(Clock clock) {
    this.clock = clock;
  }

  public Decision get(UUID principalId, Action action, ResourceRef resource, long policyVersion) {
    Entry entry = entries.get(new Key(principalId, action, resource, policyVersion));
    if (entry == null || entry.expiresAt.isBefore(clock.instant())) {
      if (entry != null) {
        entries.remove(new Key(principalId, action, resource, policyVersion));
      }
      return null;
    }
    return entry.decision;
  }

  public void put(
      UUID principalId, Action action, ResourceRef resource, long policyVersion, Decision decision) {
    if (entries.size() >= MAX_ENTRIES) {
      purge();
      if (entries.size() >= MAX_ENTRIES) {
        entries.clear();
      }
    }
    Instant expiresAt = clock.instant().plus(TTL);
    entries.put(new Key(principalId, action, resource, policyVersion), new Entry(decision, expiresAt));
  }

  public void invalidatePrincipal(UUID principalId) {
    entries.keySet().removeIf(key -> key.principalId.equals(principalId));
  }

  int size() {
    return entries.size();
  }

  private void purge() {
    Instant now = clock.instant();
    entries.entrySet().removeIf(e -> e.getValue().expiresAt.isBefore(now));
  }

  private record Key(UUID principalId, Action action, ResourceRef resource, long policyVersion) {}

  private record Entry(Decision decision, Instant expiresAt) {}
}
