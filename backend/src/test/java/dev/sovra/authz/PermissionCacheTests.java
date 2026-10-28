package dev.sovra.authz;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/** Permission-cache bounds without Spring or databases. */
class PermissionCacheTests {

  static class TickClock extends Clock {
    final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-01-01T00:00:00Z"));

    @Override
    public ZoneId getZone() {
      return ZoneId.of("UTC");
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now.get();
    }
  }

  private final TickClock clock = new TickClock();
  private final PermissionCache cache = new PermissionCache(clock);
  private final UUID principal = UUID.randomUUID();
  private final ResourceRef resource = ResourceRef.global("trust-registry", "proposals");

  @Test
  void missThenHit() {
    assertThat(cache.get(principal, Action.PROPOSE_TRUST_CHANGE, resource, 1)).isNull();
    cache.put(
        principal, Action.PROPOSE_TRUST_CHANGE, resource, 1, Decision.permit(1));
    assertThat(cache.get(principal, Action.PROPOSE_TRUST_CHANGE, resource, 1).permitted())
        .isTrue();
  }

  @Test
  void deniesAreCachedToo() {
    cache.put(
        principal,
        Action.PROPOSE_TRUST_CHANGE,
        resource,
        1,
        Decision.deny(ReasonCode.MISSING_ROLE, 1));
    Decision hit = cache.get(principal, Action.PROPOSE_TRUST_CHANGE, resource, 1);
    assertThat(hit.permitted()).isFalse();
    assertThat(hit.reasonCode()).isEqualTo(ReasonCode.MISSING_ROLE);
  }

  @Test
  void entriesExpireAfterSixtySeconds() {
    cache.put(
        principal, Action.PROPOSE_TRUST_CHANGE, resource, 1, Decision.permit(1));
    clock.now.set(clock.now.get().plus(Duration.ofSeconds(61)));
    assertThat(cache.get(principal, Action.PROPOSE_TRUST_CHANGE, resource, 1)).isNull();
  }

  @Test
  void policyVersionBumpInvalidates() {
    cache.put(
        principal, Action.PROPOSE_TRUST_CHANGE, resource, 7, Decision.permit(7));
    assertThat(cache.get(principal, Action.PROPOSE_TRUST_CHANGE, resource, 7)).isNotNull();
    assertThat(cache.get(principal, Action.PROPOSE_TRUST_CHANGE, resource, 8)).isNull();
  }

  @Test
  void principalInvalidationClearsOnlyThatPrincipal() {
    UUID other = UUID.randomUUID();
    cache.put(principal, Action.READ_AUDIT, resource, 1, Decision.permit(1));
    cache.put(other, Action.READ_AUDIT, resource, 1, Decision.permit(1));
    cache.invalidatePrincipal(principal);
    assertThat(cache.get(principal, Action.READ_AUDIT, resource, 1)).isNull();
    assertThat(cache.get(other, Action.READ_AUDIT, resource, 1)).isNotNull();
  }

  @Test
  void crossTenantResourcesNeverShareEntries() {
    ResourceRef a = ResourceRef.tenantScoped("audit", "events", UUID.randomUUID());
    ResourceRef b = ResourceRef.tenantScoped("audit", "events", UUID.randomUUID());
    cache.put(principal, Action.READ_AUDIT, a, 1, Decision.permit(1));
    assertThat(cache.get(principal, Action.READ_AUDIT, b, 1)).isNull();
  }

  @Test
  void sizeStaysBounded() {
    for (int i = 0; i < PermissionCache.MAX_ENTRIES + 100; i++) {
      cache.put(
          UUID.randomUUID(), Action.READ_AUDIT, resource, 1, Decision.permit(1));
    }
    assertThat(cache.size()).isLessThanOrEqualTo(PermissionCache.MAX_ENTRIES);
  }
}
