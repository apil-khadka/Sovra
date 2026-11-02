package dev.sovra.bff;

import dev.sovra.crypto.HolderProofException;
import dev.sovra.crypto.HolderProofs;
import dev.sovra.crypto.P256;
import jakarta.servlet.http.HttpSession;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Holder-key unlock for the dashboard (SOV-024, PROD-003). The
 * browser fetches a single-use challenge, signs it with the holder
 * private key, and posts the value plus the proof; this service
 * atomically consumes the challenge and binds the session to that
 * key's thumbprint for fifteen minutes.
 *
 * <p>Challenges live in the database ({@link ChallengeStore}), not in
 * replica memory: a challenge issued on one replica is consumable
 * exactly once from anywhere, and simultaneous unlock submissions
 * race in SQL instead of in last-write-wins session bytes. The
 * unlock grant itself stays a server-side session attribute —
 * nothing to steal from the client, nothing to replay across
 * sessions.
 */
@Service
public class HolderUnlockService {

  static final String UNLOCK_LABEL = "holder-unlock/v1";
  static final Duration CHALLENGE_TTL = Duration.ofMinutes(5);
  static final Duration UNLOCK_TTL = Duration.ofMinutes(15);

  static final String UNLOCK_ATTR = "sovra.holderUnlock";

  public record Challenge(String value, Instant expiresAt) {}

  public record Unlock(String thumbprint, Instant expiresAt) {}

  private final Clock clock;
  private final ObjectMapper mapper;
  private final ChallengeStore challenges;
  private final SecureRandom random = new SecureRandom();

  public HolderUnlockService(Clock clock, ObjectMapper mapper, ChallengeStore challenges) {
    this.clock = clock;
    this.mapper = mapper;
    this.challenges = challenges;
  }

  public Challenge challenge(UUID membershipId) {
    // A 256-bit collision is not expected in practice; the retry
    // below exists so the impossible still degrades to a fresh
    // value instead of a 500.
    for (int attempt = 0; attempt < 3; attempt++) {
      byte[] bytes = new byte[32];
      random.nextBytes(bytes);
      String value = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
      Instant expiresAt = clock.instant().plus(CHALLENGE_TTL);
      if (challenges.issue(membershipId, value, expiresAt)) {
        return new Challenge(value, expiresAt);
      }
    }
    throw new IllegalStateException("challenge store collision");
  }

  /**
   * Verifies the unlock proof and binds the session to the key. The
   * challenge is atomically consumed first, so a failed attempt can
   * never be retried against the same challenge — not even by a
   * simultaneous submission on another replica.
   */
  public Unlock unlock(
      UUID membershipId, String challengeValue, JsonNode holderJwk, String proof,
      HttpSession session) {
    if (challengeValue == null
        || challengeValue.isBlank()
        || !challenges.consume(membershipId, challengeValue, clock.instant())) {
      throw new HolderUnlockException("challenge expired");
    }
    if (holderJwk == null || holderJwk.isNull() || proof == null || proof.isBlank()) {
      throw new HolderUnlockException("holder key and proof are required");
    }
    ECPublicKey key;
    try {
      key = HolderProofs.parseP256Key(holderJwk);
    } catch (HolderProofException | IllegalArgumentException e) {
      throw new HolderUnlockException("holder key must be P-256");
    }
    String thumbprint =
        P256.thumbprint(key.getW().getAffineX(), key.getW().getAffineY());
    try {
      HolderProofs.verifyEs256(
          key, proof, UNLOCK_LABEL + "\n" + challengeValue + "\n" + thumbprint, mapper);
    } catch (HolderProofException | IllegalArgumentException e) {
      throw new HolderUnlockException("unlock proof is invalid");
    }
    Unlock bound = new Unlock(thumbprint, clock.instant().plus(UNLOCK_TTL));
    session.setAttribute(UNLOCK_ATTR, bound);
    return bound;
  }

  /** The proven thumbprint, or locked when the session never unlocked or lapsed. */
  public String requireUnlock(HttpSession session) {
    if (session == null) {
      throw new HolderLockedException();
    }
    Unlock bound = session.getAttribute(UNLOCK_ATTR) instanceof Unlock u ? u : null;
    if (bound == null) {
      throw new HolderLockedException();
    }
    if (!bound.expiresAt().isAfter(clock.instant())) {
      session.removeAttribute(UNLOCK_ATTR);
      throw new HolderLockedException();
    }
    return bound.thumbprint();
  }

  public void lock(UUID membershipId, HttpSession session) {
    session.removeAttribute(UNLOCK_ATTR);
    challenges.deleteForMember(membershipId);
  }
}
