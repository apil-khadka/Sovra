package dev.sovra.bff;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.issuance.IssuanceFixtures;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import tools.jackson.databind.ObjectMapper;

/**
 * Holder-key unlock (SOV-024): single-use challenges, ES256
 * proof verification, and session expiry. No HTTP, no
 * database: the clock is fixed and the session is a mock.
 */
class HolderUnlockServiceTests {

  static final Instant START = Instant.parse("2026-10-30T00:00:00Z");

  ObjectMapper mapper = new ObjectMapper();
  AtomicReference<Instant> now = new AtomicReference<>(START);
  Clock mutable = new Clock() {
    @Override
    public Instant instant() {
      return now.get();
    }

    @Override
    public java.time.ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(java.time.ZoneId zone) {
      return this;
    }
  };
  HolderUnlockService unlock = new HolderUnlockService(mutable, mapper);

  MockHttpSession session;

  @BeforeEach
  void setup() {
    session = new MockHttpSession();
  }

  @Test
  void validProofBindsTheSessionToTheKey() throws Exception {
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    HolderUnlockService.Challenge asked = unlock.challenge(session);
    assertThat(asked.value()).isNotBlank();

    HolderUnlockService.Unlock bound = unlock.unlock(
        session, publicJwk(holder),
        IssuanceFixtures.proofOver(
            holder,
            "holder-unlock/v1\n" + asked.value() + "\n" + IssuanceFixtures.thumbprint(holder),
            mapper));
    assertThat(bound.thumbprint()).isEqualTo(IssuanceFixtures.thumbprint(holder));
    assertThat(unlock.requireUnlock(session)).isEqualTo(bound.thumbprint());
  }

  @Test
  void challengesAreSingleUse() throws Exception {
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    HolderUnlockService.Challenge asked = unlock.challenge(session);
    String proof = IssuanceFixtures.proofOver(
        holder,
        "holder-unlock/v1\n" + asked.value() + "\n" + IssuanceFixtures.thumbprint(holder),
        mapper);
    unlock.unlock(session, publicJwk(holder), proof);
    // The same challenge never unlocks twice, even with a valid proof.
    assertThatThrownBy(() -> unlock.unlock(session, publicJwk(holder), proof))
        .isInstanceOf(HolderUnlockException.class)
        .hasMessageContaining("challenge expired");
  }

  @Test
  void expiredChallengesAndUnlocksFailClosed() throws Exception {
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    HolderUnlockService.Challenge asked = unlock.challenge(session);
    now.set(START.plus(HolderUnlockService.CHALLENGE_TTL).plusSeconds(1));
    assertThatThrownBy(() -> unlock.unlock(
        session,
        publicJwk(holder),
        IssuanceFixtures.proofOver(
            holder,
            "holder-unlock/v1\n" + asked.value() + "\n" + IssuanceFixtures.thumbprint(holder),
            mapper)))
        .isInstanceOf(HolderUnlockException.class);

    now.set(START);
    HolderUnlockService.Challenge fresh = unlock.challenge(session);
    unlock.unlock(
        session,
        publicJwk(holder),
        IssuanceFixtures.proofOver(
            holder,
            "holder-unlock/v1\n" + fresh.value() + "\n" + IssuanceFixtures.thumbprint(holder),
            mapper));
    now.set(START.plus(HolderUnlockService.UNLOCK_TTL).plusSeconds(1));
    assertThatThrownBy(() -> unlock.requireUnlock(session))
        .isInstanceOf(HolderLockedException.class);
  }

  @Test
  void wrongKeyAndTamperedProofsAreRejected() throws Exception {
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    IssuanceFixtures.HolderKeys stranger = IssuanceFixtures.generateHolder(mapper);

    HolderUnlockService.Challenge first = unlock.challenge(session);
    // Proof from another key over this challenge.
    assertThatThrownBy(() -> unlock.unlock(
        session,
        publicJwk(holder),
        IssuanceFixtures.proofOver(
            stranger,
            "holder-unlock/v1\n" + first.value() + "\n" + IssuanceFixtures.thumbprint(holder),
            mapper)))
        .isInstanceOf(HolderUnlockException.class);

    // Proof over a different challenge.
    HolderUnlockService.Challenge second = unlock.challenge(session);
    assertThatThrownBy(() -> unlock.unlock(
        session,
        publicJwk(holder),
        IssuanceFixtures.proofOver(
            holder,
            "holder-unlock/v1\n" + first.value() + "\n" + IssuanceFixtures.thumbprint(holder),
            mapper)))
        .isInstanceOf(HolderUnlockException.class);
    assertThat(second.value()).isNotEqualTo(first.value());

    // Non-JWK and non-P-256 keys.
    HolderUnlockService.Challenge third = unlock.challenge(session);
    assertThat(third.value()).isNotBlank();
    assertThatThrownBy(() -> unlock.unlock(
        session, mapper.valueToTree(Map.of("kty", "oct", "k", "x")), "proof"))
        .isInstanceOf(HolderUnlockException.class);
    assertThatThrownBy(() -> unlock.unlock(session, null, null))
        .isInstanceOf(HolderUnlockException.class);
  }

  @Test
  void lockClearsTheSession() throws Exception {
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    HolderUnlockService.Challenge asked = unlock.challenge(session);
    unlock.unlock(
        session,
        publicJwk(holder),
        IssuanceFixtures.proofOver(
            holder,
            "holder-unlock/v1\n" + asked.value() + "\n" + IssuanceFixtures.thumbprint(holder),
            mapper));
    unlock.lock(session);
    assertThatThrownBy(() -> unlock.requireUnlock(session))
        .isInstanceOf(HolderLockedException.class);
  }

  @Test
  void missingUnlockIsLocked() {
    assertThatThrownBy(() -> unlock.requireUnlock(session))
        .isInstanceOf(HolderLockedException.class);
    assertThatThrownBy(() -> unlock.requireUnlock(null))
        .isInstanceOf(HolderLockedException.class);
  }

  private tools.jackson.databind.JsonNode publicJwk(IssuanceFixtures.HolderKeys holder) {
    return mapper.valueToTree(Map.of(
        "kty", "EC", "crv", "P-256",
        "x", holder.jwk().get("x").asString(), "y", holder.jwk().get("y").asString()));
  }
}
