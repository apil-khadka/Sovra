package dev.sovra.bff;

import java.time.Instant;
import java.util.UUID;

/**
 * Single-use holder-unlock challenges (PROD-003). Challenges live in
 * the database, outside any one replica's memory, so a challenge
 * issued on replica A is consumable exactly once from anywhere —
 * including two simultaneous unlock submissions on different
 * replicas. Rows are meaningless without the holder private key.
 */
public interface ChallengeStore {

  /**
   * Records a challenge. Returns {@code false} on a value collision
   * so the caller can retry with fresh randomness.
   */
  boolean issue(UUID membershipId, String challenge, Instant expiresAt);

  /**
   * Atomically consumes one live challenge for this membership.
   * Concurrent consumers race here; at most one observes {@code true}.
   */
  boolean consume(UUID membershipId, String challenge, Instant now);

  /** Removes expired rows. Returns the number removed. */
  int deleteExpired(Instant now);

  /** Removes every outstanding challenge for one membership (lock/logout). */
  void deleteForMember(UUID membershipId);
}
