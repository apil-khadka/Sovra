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
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Holder-key unlock for the dashboard (SOV-024). The browser
 * fetches a single-use challenge, signs it with the holder
 * private key, and posts the proof; this service verifies the
 * ES256 proof and binds the session to that key's thumbprint
 * for fifteen minutes. Challenges and unlocks live in the
 * server-side session only — nothing to steal from the client,
 * nothing to replay across sessions.
 */
@Service
public class HolderUnlockService {

  static final String UNLOCK_LABEL = "holder-unlock/v1";
  static final Duration CHALLENGE_TTL = Duration.ofMinutes(5);
  static final Duration UNLOCK_TTL = Duration.ofMinutes(15);

  static final String CHALLENGE_ATTR = "sovra.holderChallenge";
  static final String UNLOCK_ATTR = "sovra.holderUnlock";

  public record Challenge(String value, Instant expiresAt) {}

  public record Unlock(String thumbprint, Instant expiresAt) {}

  private final Clock clock;
  private final ObjectMapper mapper;
  private final SecureRandom random = new SecureRandom();

  public HolderUnlockService(Clock clock, ObjectMapper mapper) {
    this.clock = clock;
    this.mapper = mapper;
  }

  public Challenge challenge(HttpSession session) {
    byte[] bytes = new byte[32];
    random.nextBytes(bytes);
    Challenge issued = new Challenge(
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes),
        clock.instant().plus(CHALLENGE_TTL));
    session.setAttribute(CHALLENGE_ATTR, issued);
    return issued;
  }

  /**
   * Verifies the unlock proof and binds the session to the key.
   * The challenge is consumed first, so a failed attempt can
   * never be retried against the same challenge.
   */
  public Unlock unlock(HttpSession session, JsonNode holderJwk, String proof) {
    Challenge asked = session.getAttribute(CHALLENGE_ATTR) instanceof Challenge c ? c : null;
    session.removeAttribute(CHALLENGE_ATTR);
    if (asked == null || !asked.expiresAt().isAfter(clock.instant())) {
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
          key, proof, UNLOCK_LABEL + "\n" + asked.value() + "\n" + thumbprint, mapper);
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

  public void lock(HttpSession session) {
    session.removeAttribute(UNLOCK_ATTR);
    session.removeAttribute(CHALLENGE_ATTR);
  }
}
