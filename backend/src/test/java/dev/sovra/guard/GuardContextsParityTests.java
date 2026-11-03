package dev.sovra.guard;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.trust.IssuerStatus;
import dev.sovra.trust.TrustService;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Shared guard-context parity: the evaluator's {@link GuardContexts}
 * factory builds byte-identical inputs to the served
 * {@link GuardService} path, so offline scoring can never drift into a
 * weaker parallel authorization. Pure unit tests.
 */
class GuardContextsParityTests {

  static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");

  private static TrustService.SnapshotView snapshot() {
    return new TrustService.SnapshotView(
        9,
        List.of(
            new TrustService.IssuerView(
                "https://sovra.example/issuers/synth-1", "one", "synthetic-only",
                List.of("https://sovra.example/vct/adult-status/1"), "synth-1", 1, null,
                NOW.minusSeconds(60), NOW.plusSeconds(3600), IssuerStatus.ACTIVE),
            new TrustService.IssuerView(
                "https://sovra.example/issuers/synth-2", "two", "synthetic-only",
                List.of(ApprovedSchemas.FJORD_VCT), "synth-2", 1, null,
                NOW.minusSeconds(60), NOW.plusSeconds(3600), IssuerStatus.ACTIVE)),
        List.of());
  }

  @Test
  void sharedFactoryMatchesServedGuardService() {
    TrustService.SnapshotView view = snapshot();
    GuardContext shared = GuardContexts.fromSnapshot(view);
    GuardContext served = GuardService.context(view);
    assertThat(shared).isEqualTo(served);
  }

  @Test
  void suspendedStandingSurvivesIntoContext() {
    TrustService.SnapshotView base = snapshot();
    TrustService.IssuerView first = base.issuers().get(0);
    TrustService.SnapshotView suspended = new TrustService.SnapshotView(
        base.version(),
        List.of(
            new TrustService.IssuerView(
                first.issuerId(), first.displayName(), first.scope(),
                first.credentialTypes(), first.keyId(), first.keyVersion(),
                first.publicKeyJwk(), first.validFrom(), first.validThrough(),
                IssuerStatus.SUSPENDED),
            base.issuers().get(1)),
        base.policies());
    GuardContext context = GuardContexts.fromSnapshot(suspended);
    assertThat(context.trustedIssuers().get(first.issuerId()).status())
        .isEqualTo(IssuerStatus.SUSPENDED);
    CandidatePlan plan = new CandidatePlan(
        "pln_parity_001", "age_over_18", first.issuerId(),
        "https://sovra.example/vct/adult-status/1", List.of("adultOver18"),
        List.of(new EvidenceCitation(GuardPolicies.POLICY_ID, GuardPolicies.SECTION_ID)),
        GuardPolicies.POLICY_ID, GuardPolicies.POLICY_VERSION,
        Recommendation.CANDIDATE_ONLY);
    GuardVerdict verdict = PlanGuard.validate(
        plan, context,
        new SelectedPolicy(GuardPolicies.POLICY_ID, GuardPolicies.POLICY_VERSION),
        new GuardInputs(PlanGuard.RULES_VERSION, NOW));
    assertThat(verdict.accepted()).isFalse();
    assertThat(verdict.code()).isEqualTo(GuardOutcome.GUARD_ISSUER_EPOCH_INVALID);
  }
}
