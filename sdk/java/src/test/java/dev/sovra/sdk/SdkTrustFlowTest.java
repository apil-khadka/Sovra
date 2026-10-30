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

      // Read-modify-write: carry every authorized issuer and policy
      // forward so the test never evicts the shared stack's issuers.
      List<Map<String, Object>> carried = new java.util.ArrayList<>();
      for (OpsClient.SnapshotIssuer existing : current.issuers()) {
        // Skip our own test issuer id; a fresh row is appended below so
        // repeated runs never accumulate duplicate entries.
        if ("sdk-onboard-issuer".equals(existing.issuerId())) {
          continue;
        }
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
        carried.add(row);
      }
      List<Map<String, Object>> policies = new java.util.ArrayList<>();
      for (OpsClient.SnapshotPolicy existing : current.policies()) {
        policies.add(Map.of("rpId", existing.rpId(), "purpose", existing.purpose(),
            "allowedTypes", existing.allowedTypes(), "maxAssurance", existing.maxAssurance()));
      }
      String keyId = "sdk-" + Idempotency.mint().substring(0, 8);
      carried.add(Map.of(
          "issuerId", "sdk-onboard-issuer", "displayName", "SDK onboard issuer",
          "scope", "adult-status", "credentialTypes", List.of(ADULT_VCT), "keyId", keyId,
          "keyVersion", 1,
          "publicKeyJwk", Map.of("kty", "EC", "crv", "P-256", "kid", keyId,
              "x", "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
              "y", "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"),
          "validFrom", Instant.now().minusSeconds(60).toString(),
          "validThrough", Instant.now().plusSeconds(3600).toString(), "status", "ACTIVE"));
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
      assertThat(makerClient.ops.snapshot().version())
          .isEqualTo(Long.parseLong(proposed.version()));
    }
  }
}
