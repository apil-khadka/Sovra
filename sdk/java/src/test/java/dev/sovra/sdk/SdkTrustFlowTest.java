package dev.sovra.sdk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

/** Trust lifecycle (SOV-021): queue, onboard, approve, activate — with the two-person rule. */
class SdkTrustFlowTest extends SdkLiveBase {

  @Test
  void trustAdminsOnboardThroughMakerChecker() throws Exception {
    MachineAccount maker = mintAccount("sdk-maker", "TRUST_ADMIN");
    MachineAccount checker = mintAccount("sdk-checker", "TRUST_ADMIN");
    try (SovraClient makerClient = clientFor(maker.token());
        SovraClient checkerClient = clientFor(checker.token())) {
      List<TrustClient.ProposalSummary> before = makerClient.trust.proposals();
      assertThat(before).isNotNull();
      OpsClient.TrustSnapshot current = makerClient.ops.snapshot();
      assertThat(current.issuers()).isNotEmpty();

      // Read-modify-write with explicit test-fixture ownership. Both SDK
      // suites own BOTH test issuer ids: each run refreshes its own row
      // and repairs the sibling's row when stale, so long-lived
      // disposable stacks stay repeatable whichever suite ran last.
      // Non-test issuers/policies are always carried forward untouched;
      // an expired non-test issuer fails loudly instead of being
      // dropped, preserving historical authority.
      String ownIssuer = "sdk-onboard-issuer";
      String siblingIssuer = "ts-onboard-issuer";
      java.util.Set<String> testIssuers = java.util.Set.of(ownIssuer, siblingIssuer);
      List<Map<String, Object>> carried = new java.util.ArrayList<>();
      Map<String, OpsClient.SnapshotIssuer> nonTestExpected = new java.util.LinkedHashMap<>();
      boolean siblingCarried = false;
      // A repaired sibling row is ACTIVE; a carried sibling keeps the
      // standing it had — a fresh SUSPENDED row is preserved as-is and
      // never reactivated merely to satisfy the final assertions.
      String expectedSiblingStatus = "ACTIVE";
      for (OpsClient.SnapshotIssuer existing : current.issuers()) {
        // Own row is always replaced below so repeats never duplicate.
        if (ownIssuer.equals(existing.issuerId())) {
          continue;
        }
        if (testIssuers.contains(existing.issuerId())) {
          boolean siblingFresh = isFreshTestRow(existing);
          if (!siblingFresh) {
            continue; // Stale sibling fixture: repaired below.
          }
          siblingCarried = true;
          expectedSiblingStatus = existing.status();
          carried.add(carriedRow(existing));
          continue;
        }
        Instant validThrough = Instant.parse(existing.validThrough());
        if (!validThrough.isAfter(Instant.now())) {
          throw new AssertionError("non-test issuer " + existing.issuerId()
              + " expired at " + existing.validThrough()
              + "; refusing to drop historical authority — rotate it manually");
        }
        nonTestExpected.put(existing.issuerId(), existing);
        carried.add(carriedRow(existing));
      }
      List<Map<String, Object>> policies = new java.util.ArrayList<>();
      for (OpsClient.SnapshotPolicy existing : current.policies()) {
        policies.add(Map.of("rpId", existing.rpId(), "purpose", existing.purpose(),
            "allowedTypes", existing.allowedTypes(), "maxAssurance", existing.maxAssurance()));
      }
      carried.add(freshTestIssuer(ownIssuer));
      if (!siblingCarried) {
        carried.add(freshTestIssuer(siblingIssuer));
      }
      TrustClient.ProposeResult proposed =
          makerClient.trust.propose(carried, policies, "sdk onboarding test");
      assertThat(Long.parseLong(proposed.version())).isGreaterThan(current.version());

      List<TrustClient.ProposalSummary> queue = checkerClient.trust.proposals();
      assertThat(queue.stream().map(TrustClient.ProposalSummary::proposalId))
          .contains(proposed.proposalId());

      // Maker cannot approve their own onboarding.
      assertThatThrownBy(() -> makerClient.trust.approve(proposed.proposalId()))
          .isInstanceOf(SovraApiError.class)
          .satisfies(e -> assertThat(((SovraApiError) e).status()).isEqualTo(403));

      TrustClient.ApproveResult approved =
          checkerClient.trust.approve(proposed.proposalId());
      assertThat(approved.proposalId()).isEqualTo(proposed.proposalId());
      TrustClient.ActivateResult activated =
          checkerClient.trust.activate(Long.parseLong(proposed.version()));
      assertThat(activated.version()).isEqualTo(proposed.version());
      OpsClient.TrustSnapshot after = makerClient.ops.snapshot();
      assertThat(after.version()).isEqualTo(Long.parseLong(proposed.version()));
      // Regression for both test-issuer histories: whichever suite ran
      // last, both fixtures converge to fresh rows. The own row is always
      // ACTIVE; the sibling row is ACTIVE when repaired, or keeps its
      // carried standing (SUSPENDED rows are preserved, never
      // reactivated by the test).
      OpsClient.SnapshotIssuer own = after.issuers().stream()
          .filter(i -> ownIssuer.equals(i.issuerId())).findFirst().orElse(null);
      assertThat(own).as("expected test issuer %s in the new snapshot", ownIssuer).isNotNull();
      assertThat(own.status()).isEqualTo("ACTIVE");
      assertThat(Instant.parse(own.validThrough())).isAfter(Instant.now());
      OpsClient.SnapshotIssuer sib = after.issuers().stream()
          .filter(i -> siblingIssuer.equals(i.issuerId())).findFirst().orElse(null);
      assertThat(sib).as("expected test issuer %s in the new snapshot", siblingIssuer).isNotNull();
      assertThat(sib.status()).isEqualTo(expectedSiblingStatus);
      assertThat(Instant.parse(sib.validThrough())).isAfter(Instant.now());
      // Every non-test issuer survives byte-identically (full row
      // content, not just presence), with no duplicates, and every
      // policy survives with identical content.
      assertThat(after.issuers().stream()
          .filter(i -> nonTestExpected.containsKey(i.issuerId())).count())
          .isEqualTo(nonTestExpected.size());
      for (Map.Entry<String, OpsClient.SnapshotIssuer> expected : nonTestExpected.entrySet()) {
        OpsClient.SnapshotIssuer row = after.issuers().stream()
            .filter(i -> expected.getKey().equals(i.issuerId())).findFirst().orElse(null);
        assertThat(row)
            .as("non-test issuer %s must survive the test rotation", expected.getKey()).isNotNull();
        assertThat(row).isEqualTo(expected.getValue());
      }
      assertThat(after.policies()).containsExactlyInAnyOrderElementsOf(current.policies());
    }
  }

  private static Map<String, Object> carriedRow(OpsClient.SnapshotIssuer existing) {
    Map<String, Object> row = new java.util.HashMap<>();
    row.put("issuerId", existing.issuerId());
    row.put("displayName", existing.displayName());
    row.put("scope", existing.scope());
    row.put("credentialTypes", existing.credentialTypes());
    row.put("keyId", existing.keyId());
    row.put("keyVersion", existing.keyVersion());
    row.put("publicKeyJwk", existing.publicKeyJwk());
    row.put("validFrom", existing.validFrom());
    row.put("validThrough", existing.validThrough());
    row.put("status", existing.status());
    return row;
  }

  private static boolean isFreshTestRow(OpsClient.SnapshotIssuer existing) {
    try {
      boolean windowOk = Instant.parse(existing.validThrough()).isAfter(Instant.now());
      boolean statusOk = "ACTIVE".equals(existing.status()) || "SUSPENDED".equals(existing.status());
      return windowOk && statusOk;
    } catch (Exception e) {
      return false;
    }
  }

  private static Map<String, Object> freshTestIssuer(String issuerId) {
    String prefix = issuerId.startsWith("sdk-") ? "sdk-" : "ts-";
    String keyId = prefix + Idempotency.mint().substring(0, 8);
    String displayName = "sdk-onboard-issuer".equals(issuerId)
        ? "SDK onboard issuer" : "TS onboard issuer";
    return Map.of(
        "issuerId", issuerId, "displayName", displayName,
        "scope", "adult-status", "credentialTypes", List.of(ADULT_VCT), "keyId", keyId,
        "keyVersion", 1,
        "publicKeyJwk", Map.of("kty", "EC", "crv", "P-256", "kid", keyId,
            "x", "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y", "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"),
        "validFrom", Instant.now().minusSeconds(60).toString(),
        "validThrough", Instant.now().plusSeconds(30L * 24 * 3600).toString(), "status", "ACTIVE");
  }
}
