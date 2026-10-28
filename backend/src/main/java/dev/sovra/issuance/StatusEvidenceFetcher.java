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

  record StatusEvidence(Status status, Instant fetchedAt, Duration maxAge) {}
}
