package dev.sovra.planning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.guard.ApprovedSchemas;
import dev.sovra.guard.CandidatePlan;
import dev.sovra.guard.EvidenceCitation;
import dev.sovra.guard.GuardPolicies;
import dev.sovra.guard.Recommendation;
import dev.sovra.issuance.LocalDevSigner;
import dev.sovra.trust.IssuerStatus;
import dev.sovra.trust.TrustService;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Discovery-scope validation and plan-to-scope binding: scope shape is
 * bounded pre-model, unknown scope values never 400, and an out-of-scope
 * candidate becomes NO_PATH (never rewritten into scope). Pure unit tests.
 */
class DiscoveryScopeTests {

  static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");

  private static TrustService.SnapshotView snapshot() {
    return new TrustService.SnapshotView(
        7,
        List.of(
            new TrustService.IssuerView(
                "https://sovra.example/issuers/synth-1", "one", "synthetic-only",
                List.of("https://sovra.example/vct/adult-status/1"), "synth-1", 1, null,
                NOW.minusSeconds(60), NOW.plusSeconds(3600), IssuerStatus.ACTIVE),
            new TrustService.IssuerView(
                LocalDevSigner.SECOND_ISSUER_ID, "two", "synthetic-only",
                List.of(ApprovedSchemas.FJORD_VCT), "synth-2", 1, null,
                NOW.minusSeconds(60), NOW.plusSeconds(3600), IssuerStatus.ACTIVE)),
        List.of());
  }

  private static PlanningIntent intent(List<String> issuers, List<String> types) {
    return PlanningIntents.validate(
        "https://rp.example/x", "https://rp.example/x/cb", "p", "age_over_18",
        GuardPolicies.MAPPED_POLICY_ID, GuardPolicies.MAPPED_POLICY_VERSION,
        List.of("adultOver18"), issuers, types, null);
  }

  private static PlanningResult candidate(String issuer, String type, String claim) {
    var plan = new CandidatePlan(
        "pln_scope_001", "age_over_18", issuer, type, List.of(claim),
        List.of(new EvidenceCitation(
            GuardPolicies.MAPPED_POLICY_ID, GuardPolicies.MAPPED_SECTION_ID)),
        GuardPolicies.MAPPED_POLICY_ID, GuardPolicies.MAPPED_POLICY_VERSION,
        Recommendation.CANDIDATE_ONLY);
    return PlanningResult.live(
        plan, Recommendation.CANDIDATE_ONLY, "injected", "test-model", "hash", 2, 9L, 11L);
  }

  @Test
  void unscopedIntentsPassThroughUnchanged() {
    PlanningIntent plain = PlanningIntents.validate(
        "https://rp.example/x", "https://rp.example/x/cb", "p", "age_over_18",
        GuardPolicies.POLICY_ID, GuardPolicies.POLICY_VERSION, List.of("adultOver18"));
    assertThat(plain.scoped()).isFalse();
    PlanningResult in = candidate(
        "https://sovra.example/issuers/synth-1",
        "https://sovra.example/vct/adult-status/1", "adultOver18");
    assertThat(PlanningService.bindToScope(in, plain, snapshot())).isSameAs(in);
  }

  @Test
  void inScopeCandidatePassesThrough() {
    PlanningIntent scoped = intent(List.of(LocalDevSigner.SECOND_ISSUER_ID), null);
    PlanningResult in = candidate(
        LocalDevSigner.SECOND_ISSUER_ID, ApprovedSchemas.FJORD_VCT, "isAdult");
    assertThat(PlanningService.bindToScope(in, scoped, snapshot())).isSameAs(in);
  }

  @Test
  void outOfScopeIssuerBecomesNoPath() {
    PlanningIntent scoped = intent(List.of(LocalDevSigner.SECOND_ISSUER_ID), null);
    PlanningResult in = candidate(
        "https://sovra.example/issuers/synth-1",
        "https://sovra.example/vct/adult-status/1", "adultOver18");
    PlanningResult out = PlanningService.bindToScope(in, scoped, snapshot());
    assertThat(out.recommendation()).isEqualTo(Recommendation.NO_PATH);
    assertThat(out.plan()).isNull();
    assertThat(out.reason()).contains("outside the requested discovery scope");
    assertThat(out.mode()).isEqualTo(in.mode());
  }

  @Test
  void outOfScopeTypeBecomesNoPath() {
    PlanningIntent scoped = intent(null, List.of(ApprovedSchemas.FJORD_VCT));
    PlanningResult in = candidate(
        "https://sovra.example/issuers/synth-1",
        "https://sovra.example/vct/adult-status/1", "adultOver18");
    PlanningResult out = PlanningService.bindToScope(in, scoped, snapshot());
    assertThat(out.recommendation()).isEqualTo(Recommendation.NO_PATH);
    assertThat(out.plan()).isNull();
  }

  @Test
  void unknownScopeValuesValidateButMatchNothing() {
    // Unknown values are untrusted hints: intent validation passes (no
    // 400); the narrowed pick simply finds nothing (NO_PATH at plan time).
    PlanningIntent scoped = intent(List.of("https://sovra.example/issuers/retired-9"), null);
    assertThat(scoped.scoped()).isTrue();
    PlanningResult result = FixturePlanner.plan(scoped, snapshot(), NOW, "hash");
    assertThat(result.recommendation()).isEqualTo(Recommendation.NO_PATH);
    assertThat(result.plan()).isNull();
  }

  @Test
  void malformedScopeShapesStillFailPreModel() {
    assertThatThrownBy(() -> intent(List.of("x".repeat(513)), null))
        .isInstanceOf(InvalidPlanningException.class);
    assertThatThrownBy(() -> intent(
            List.of("a", "b", "c", "d", "e", "f", "g", "h", "i"), null))
        .isInstanceOf(InvalidPlanningException.class);
  }

  @Test
  void fixtureRespectsScopeGenerically() {
    PlanningIntent scoped = intent(List.of(LocalDevSigner.SECOND_ISSUER_ID), null);
    PlanningResult result = FixturePlanner.plan(
        scoped, snapshot(), NOW, "hash");
    assertThat(result.recommendation()).isEqualTo(Recommendation.CANDIDATE_ONLY);
    assertThat(result.plan().candidateIssuerId()).isEqualTo(LocalDevSigner.SECOND_ISSUER_ID);
    assertThat(result.plan().credentialType()).isEqualTo(ApprovedSchemas.FJORD_VCT);
    assertThat(result.plan().claimPaths()).containsExactly("isAdult");
  }
}
