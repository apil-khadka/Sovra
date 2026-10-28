package dev.sovra.issuance;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Credential status evidence (SOV-004 section 3). Unknown is a
 * first-class outcome — never an exception swallowed into success.
 */
public interface StatusEvidenceFetcher {

  StatusEvidence fetch(UUID credentialId);

  enum Status {
    VALID,
    REVOKED,
    UNKNOWN
  }

  /**
   * Version counts terminal revocations: 1 while never revoked, bumped
   * on every revocation. Decisions record it as their status evidence
   * version, so a revocation race leaves an exact audit trail.
   */
  record StatusEvidence(Status status, long version, Instant fetchedAt, Duration maxAge) {

    /** Declared freshness bound (SOV-001 section 4: 15 minutes). */
    public boolean fresh(Instant now) {
      return fetchedAt.plus(maxAge).isAfter(now);
    }
  }
}
