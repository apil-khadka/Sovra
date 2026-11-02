package dev.sovra.bff;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.issuance.IssuanceFixtures;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import tools.jackson.databind.ObjectMapper;

/**
 * Holder-key unlock (SOV-024, PROD-003): single-use challenges, ES256
 * proof verification, and session expiry. No HTTP, no database: the
 * clock is fixed, the session is a mock, and the challenge store is
 * an in-memory fake with the production store's exact atomicity
 * (conditional remove). The JDBC store proves the same semantics
 * against real SQL in JdbcChallengeStoreTests.
 */
class HolderUnlockServiceTests {

  static final Instant START = Instant.parse("2026-10-30T00:00:00Z");
  static final UUID MEMBER = UUID.fromString("11111111-1111-4111-8111-111111111111");

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

  /** Mirrors JdbcChallengeStore: atomic conditional consume, member-scoped. */
  static final class MemoryChallengeStore implements ChallengeStore {
    record Row(UUID member, Instant expiresAt) {}

    final Map<String, Row> rows = new ConcurrentHashMap<>();

    @Override
    public boolean issue(UUID membershipId, String challenge, Instant expiresAt) {
      return rows.putIfAbsent(challenge, new Row(membershipId, expiresAt)) == null;
    }

    @Override
    public boolean consume(UUID membershipId, String challenge, Instant now) {
      Row row = rows.get(challenge);
      if (row == null || !row.member().equals(membershipId) || !row.expiresAt().isAfter(now)) {
        return false;
      }
      return rows.remove(challenge, row);
    }

    @Override
    public int deleteExpired(Instant now) {
      int removed = 0;
      for (var entry : rows.entrySet()) {
        if (!entry.getValue().expiresAt().isAfter(now) && rows.remove(entry.getKey(), entry.getValue())) {
          removed++;
        }
      }
      return removed;
    }

    @Override
    public void deleteForMember(UUID membershipId) {
      rows.entrySet().removeIf(entry -> entry.getValue().member().equals(membershipId));
    }
  }

  MemoryChallengeStore store = new MemoryChallengeStore();
  HolderUnlockService unlock = new HolderUnlockService(mutable, mapper, store);

  MockHttpSession session;

  @BeforeEach
  void setup() {
    session = new MockHttpSession();
  }

  @Test
  void validProofBindsTheSessionToTheKey() throws Exception {
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    HolderUnlockService.Challenge asked = unlock.challenge(MEMBER);
    assertThat(asked.value()).isNotBlank();

    HolderUnlockService.Unlock bound = unlock.unlock(
        MEMBER, asked.value(), publicJwk(holder),
        IssuanceFixtures.proofOver(
            holder,
            "holder-unlock/v1\n" + asked.value() + "\n" + IssuanceFixtures.thumbprint(holder),
            mapper),
        session);
    assertThat(bound.thumbprint()).isEqualTo(IssuanceFixtures.thumbprint(holder));
    assertThat(unlock.requireUnlock(session)).isEqualTo(bound.thumbprint());
  }

  @Test
  void challengesAreSingleUse() throws Exception {
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    HolderUnlockService.Challenge asked = unlock.challenge(MEMBER);
    String proof = IssuanceFixtures.proofOver(
        holder,
        "holder-unlock/v1\n" + asked.value() + "\n" + IssuanceFixtures.thumbprint(holder),
        mapper);
    unlock.unlock(MEMBER, asked.value(), publicJwk(holder), proof, session);
    // The same challenge never unlocks twice, even with a valid proof.
    assertThatThrownBy(() -> unlock.unlock(MEMBER, asked.value(), publicJwk(holder), proof, session))
        .isInstanceOf(HolderUnlockException.class)
        .hasMessageContaining("challenge expired");
  }

  @Test
  void challengesAreMemberScoped() throws Exception {
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    HolderUnlockService.Challenge asked = unlock.challenge(MEMBER);
    UUID stranger = UUID.randomUUID();
    assertThatThrownBy(() -> unlock.unlock(
        stranger,
        asked.value(),
        publicJwk(holder),
        IssuanceFixtures.proofOver(
            holder,
            "holder-unlock/v1\n" + asked.value() + "\n" + IssuanceFixtures.thumbprint(holder),
            mapper),
        session))
        .isInstanceOf(HolderUnlockException.class)
        .hasMessageContaining("challenge expired");
  }

  @Test
  void expiredChallengesAndUnlocksFailClosed() throws Exception {
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    HolderUnlockService.Challenge asked = unlock.challenge(MEMBER);
    now.set(START.plus(HolderUnlockService.CHALLENGE_TTL).plusSeconds(1));
    assertThatThrownBy(() -> unlock.unlock(
        MEMBER,
        asked.value(),
        publicJwk(holder),
        IssuanceFixtures.proofOver(
            holder,
            "holder-unlock/v1\n" + asked.value() + "\n" + IssuanceFixtures.thumbprint(holder),
            mapper),
        session))
        .isInstanceOf(HolderUnlockException.class);

    now.set(START);
    HolderUnlockService.Challenge fresh = unlock.challenge(MEMBER);
    unlock.unlock(
        MEMBER,
        fresh.value(),
        publicJwk(holder),
        IssuanceFixtures.proofOver(
            holder,
            "holder-unlock/v1\n" + fresh.value() + "\n" + IssuanceFixtures.thumbprint(holder),
            mapper),
        session);
    now.set(START.plus(HolderUnlockService.UNLOCK_TTL).plusSeconds(1));
    assertThatThrownBy(() -> unlock.requireUnlock(session))
        .isInstanceOf(HolderLockedException.class);
  }

  @Test
  void wrongKeyAndTamperedProofsAreRejected() throws Exception {
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    IssuanceFixtures.HolderKeys stranger = IssuanceFixtures.generateHolder(mapper);

    HolderUnlockService.Challenge first = unlock.challenge(MEMBER);
    // Proof from another key over this challenge.
    assertThatThrownBy(() -> unlock.unlock(
        MEMBER,
        first.value(),
        publicJwk(holder),
        IssuanceFixtures.proofOver(
            stranger,
            "holder-unlock/v1\n" + first.value() + "\n" + IssuanceFixtures.thumbprint(holder),
            mapper),
        session))
        .isInstanceOf(HolderUnlockException.class);

    // Proof over a different challenge.
    HolderUnlockService.Challenge second = unlock.challenge(MEMBER);
    assertThatThrownBy(() -> unlock.unlock(
        MEMBER,
        second.value(),
        publicJwk(holder),
        IssuanceFixtures.proofOver(
            holder,
            "holder-unlock/v1\n" + first.value() + "\n" + IssuanceFixtures.thumbprint(holder),
            mapper),
        session))
        .isInstanceOf(HolderUnlockException.class);
    assertThat(second.value()).isNotEqualTo(first.value());

    // Non-JWK and non-P-256 keys.
    HolderUnlockService.Challenge third = unlock.challenge(MEMBER);
    assertThat(third.value()).isNotBlank();
    assertThatThrownBy(() -> unlock.unlock(
        MEMBER, third.value(), mapper.valueToTree(Map.of("kty", "oct", "k", "x")), "proof", session))
        .isInstanceOf(HolderUnlockException.class);
    HolderUnlockService.Challenge fourth = unlock.challenge(MEMBER);
    assertThatThrownBy(() -> unlock.unlock(MEMBER, fourth.value(), null, null, session))
        .isInstanceOf(HolderUnlockException.class);
  }

  @Test
  void lockClearsTheSessionAndOutstandingChallenges() throws Exception {
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    HolderUnlockService.Challenge asked = unlock.challenge(MEMBER);
    unlock.unlock(
        MEMBER,
        asked.value(),
        publicJwk(holder),
        IssuanceFixtures.proofOver(
            holder,
            "holder-unlock/v1\n" + asked.value() + "\n" + IssuanceFixtures.thumbprint(holder),
            mapper),
        session);
    HolderUnlockService.Challenge pending = unlock.challenge(MEMBER);
    unlock.lock(MEMBER, session);
    assertThatThrownBy(() -> unlock.requireUnlock(session))
        .isInstanceOf(HolderLockedException.class);
    // Outstanding challenges die with the lock.
    assertThatThrownBy(() -> unlock.unlock(
        MEMBER,
        pending.value(),
        publicJwk(holder),
        IssuanceFixtures.proofOver(
            holder,
            "holder-unlock/v1\n" + pending.value() + "\n" + IssuanceFixtures.thumbprint(holder),
            mapper),
        session))
        .isInstanceOf(HolderUnlockException.class);
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
