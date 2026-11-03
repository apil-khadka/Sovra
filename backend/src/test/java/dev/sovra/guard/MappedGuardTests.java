package dev.sovra.guard;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.trust.IssuerStatus;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Guard rules v2 over governed schemas (type-specific binding plus
 * semantic-outcome binding): mapped unfamiliar wire pairs accept under the
 * mapped policy only; cross-type substitution, old-policy alias use, and
 * employment tenure all fail closed with distinct codes. Pure unit tests.
 */
class MappedGuardTests {

  static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");
  static final String SYNTH_1 = "https://sovra.example/issuers/synth-1";
  static final String SYNTH_2 = "https://sovra.example/issuers/synth-2";
  static final String ADULT_VCT = "https://sovra.example/vct/adult-status/1";

  private static GuardContext context() {
    Map<String, TrustedIssuer> issuers = new HashMap<>();
    issuers.put(SYNTH_1, issuer(SYNTH_1, List.of(ADULT_VCT)));
    issuers.put(SYNTH_2, issuer(SYNTH_2, List.of(
        ApprovedSchemas.FJORD_VCT, ApprovedSchemas.HARBOR_VCT,
        ApprovedSchemas.EMPLOYMENT_VCT)));
    Map<String, PolicyDocument> policies = new HashMap<>(GuardPolicies.documents());
    policies.putAll(ApprovedSchemas.documents());
    return new GuardContext(Map.copyOf(issuers), Map.copyOf(policies));
  }

  private static TrustedIssuer issuer(String id, List<String> types) {
    List<String> union = types.stream()
        .flatMap(t -> GuardClaims.forType(t).stream()).toList();
    return new TrustedIssuer(
        id, types, union, List.of("k"), IssuerStatus.ACTIVE,
        NOW.minusSeconds(60), NOW.plusSeconds(3600));
  }

  private static CandidatePlan plan(
      String issuer, String type, String claim, String policyId, String section) {
    return new CandidatePlan(
        "pln_mapped_001", "age_over_18", issuer, type, List.of(claim),
        List.of(new EvidenceCitation(policyId, section)),
        policyId, "1", Recommendation.CANDIDATE_ONLY);
  }

  private static GuardVerdict decide(CandidatePlan plan, SelectedPolicy selected) {
    return PlanGuard.validate(
        plan, context(), selected, new GuardInputs(PlanGuard.RULES_VERSION, NOW));
  }

  @Test
  void mappedFjordPairAcceptsUnderMappedPolicy() {
    CandidatePlan fjord = plan(
        SYNTH_2, ApprovedSchemas.FJORD_VCT, "isAdult",
        GuardPolicies.MAPPED_POLICY_ID, GuardPolicies.MAPPED_SECTION_ID);
    GuardVerdict verdict = decide(
        fjord, new SelectedPolicy(GuardPolicies.MAPPED_POLICY_ID, "1"));
    assertThat(verdict.accepted()).isTrue();
    assertThat(verdict.code()).isEqualTo(GuardOutcome.GUARD_ACCEPTED);
  }

  @Test
  void mappedHarborPairAcceptsUnderMappedPolicy() {
    CandidatePlan harbor = plan(
        SYNTH_2, ApprovedSchemas.HARBOR_VCT, "qualifiesAsAdult",
        GuardPolicies.MAPPED_POLICY_ID, GuardPolicies.MAPPED_SECTION_ID);
    GuardVerdict verdict = decide(
        harbor, new SelectedPolicy(GuardPolicies.MAPPED_POLICY_ID, "1"));
    assertThat(verdict.accepted()).isTrue();
  }

  @Test
  void legacyPairStillAcceptsUnderLegacyPolicy() {
    CandidatePlan legacy = plan(
        SYNTH_1, ADULT_VCT, "adultOver18",
        GuardPolicies.POLICY_ID, GuardPolicies.SECTION_ID);
    GuardVerdict verdict = decide(
        legacy, new SelectedPolicy(GuardPolicies.POLICY_ID, "1"));
    assertThat(verdict.accepted()).isTrue();
  }

  @Test
  void legacyPairAcceptsUnderMappedPolicyToo() {
    CandidatePlan legacy = plan(
        SYNTH_1, ADULT_VCT, "adultOver18",
        GuardPolicies.MAPPED_POLICY_ID, GuardPolicies.MAPPED_SECTION_ID);
    GuardVerdict verdict = decide(
        legacy, new SelectedPolicy(GuardPolicies.MAPPED_POLICY_ID, "1"));
    assertThat(verdict.accepted()).isTrue();
  }

  @Test
  void newAliasUnderOldPolicyIsOverbroad() {
    CandidatePlan alias = plan(
        SYNTH_2, ApprovedSchemas.FJORD_VCT, "isAdult",
        GuardPolicies.POLICY_ID, GuardPolicies.SECTION_ID);
    GuardVerdict verdict = decide(
        alias, new SelectedPolicy(GuardPolicies.POLICY_ID, "1"));
    assertThat(verdict.accepted()).isFalse();
    assertThat(verdict.code()).isEqualTo(GuardOutcome.GUARD_OVERBROAD_DISCLOSURE);
  }

  @Test
  void crossTypeSubstitutionFailsDespiteUnionMembership() {
    // synth-2's union contains isAdult (via fjord), but the plan names the
    // adult-status type with it: union membership must not authorize.
    CandidatePlan crossed = new CandidatePlan(
        "pln_mapped_002", "age_over_18", SYNTH_2, ADULT_VCT, List.of("isAdult"),
        List.of(new EvidenceCitation(
            GuardPolicies.MAPPED_POLICY_ID, GuardPolicies.MAPPED_SECTION_ID)),
        GuardPolicies.MAPPED_POLICY_ID, "1", Recommendation.CANDIDATE_ONLY);
    // Widen the fixture issuer to hold both types so the union check alone
    // would pass; the type-specific check must still refuse.
    Map<String, TrustedIssuer> issuers = new HashMap<>();
    issuers.put(SYNTH_2, issuer(SYNTH_2, List.of(ADULT_VCT, ApprovedSchemas.FJORD_VCT)));
    Map<String, PolicyDocument> policies = new HashMap<>(GuardPolicies.documents());
    policies.putAll(ApprovedSchemas.documents());
    GuardVerdict verdict = PlanGuard.validate(
        crossed,
        new GuardContext(Map.copyOf(issuers), Map.copyOf(policies)),
        new SelectedPolicy(GuardPolicies.MAPPED_POLICY_ID, "1"),
        new GuardInputs(PlanGuard.RULES_VERSION, NOW));
    assertThat(verdict.accepted()).isFalse();
    assertThat(verdict.code()).isEqualTo(GuardOutcome.GUARD_UNTRUSTED_CLAIM);
  }

  @Test
  void employmentTenureNeverSatisfiesAge() {
    CandidatePlan tenure = plan(
        SYNTH_2, ApprovedSchemas.EMPLOYMENT_VCT, "yearsInEmployment",
        GuardPolicies.MAPPED_POLICY_ID, GuardPolicies.MAPPED_SECTION_ID);
    GuardVerdict verdict = decide(
        tenure, new SelectedPolicy(GuardPolicies.MAPPED_POLICY_ID, "1"));
    assertThat(verdict.accepted()).isFalse();
    assertThat(verdict.code()).isIn(
        GuardOutcome.GUARD_UNTRUSTED_CLAIM, GuardOutcome.GUARD_UNSUPPORTED_OUTCOME);
  }

  @Test
  void unknownWirePairFailsClosed() {
    CandidatePlan unknown = plan(
        SYNTH_2, "https://sovra.example/vct/novel/9", "mysteryFlag",
        GuardPolicies.MAPPED_POLICY_ID, GuardPolicies.MAPPED_SECTION_ID);
    GuardVerdict verdict = decide(
        unknown, new SelectedPolicy(GuardPolicies.MAPPED_POLICY_ID, "1"));
    assertThat(verdict.accepted()).isFalse();
    assertThat(verdict.code()).isIn(
        GuardOutcome.GUARD_UNTRUSTED_CREDENTIAL_TYPE, GuardOutcome.GUARD_UNTRUSTED_CLAIM);
  }

  @Test
  void oldRulesStringIsRejectedForNewRules() {
    CandidatePlan legacy = plan(
        SYNTH_1, ADULT_VCT, "adultOver18",
        GuardPolicies.POLICY_ID, GuardPolicies.SECTION_ID);
    GuardVerdict verdict = PlanGuard.validate(
        legacy, context(), new SelectedPolicy(GuardPolicies.POLICY_ID, "1"),
        new GuardInputs("sovra-guard/1", NOW));
    assertThat(verdict.accepted()).isFalse();
    assertThat(verdict.code()).isEqualTo(GuardOutcome.GUARD_MALFORMED_PLAN);
  }
}
