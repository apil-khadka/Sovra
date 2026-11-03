package dev.sovra.guard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.issuance.SyntheticJwtEncoder;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Shared versioned schema/semantics registry (governed discovery): one
 * frozen table binds each wire pair to its semantic; cross-type reuse,
 * unknown pairs, and employment tenure never authorize age proofs.
 * Pure unit tests, no Spring.
 */
class GovernedRegistryTests {

  @Test
  void registryIsVersionedAndFrozen() {
    assertThat(ApprovedSchemas.version()).isEqualTo("sovra-synthetic-schemas/1");
    assertThat(ApprovedSchemas.entries()).hasSize(4);
  }

  @Test
  void compatibleTypesAttestExactlyTheirWireClaim() {
    assertThat(ApprovedSchemas.forType(SyntheticJwtEncoder.ADULT_VCT))
        .containsExactly("adultOver18");
    assertThat(ApprovedSchemas.forType(ApprovedSchemas.FJORD_VCT)).containsExactly("isAdult");
    assertThat(ApprovedSchemas.forType(ApprovedSchemas.HARBOR_VCT))
        .containsExactly("qualifiesAsAdult");
  }

  @Test
  void legacyCorpusTypeNameResolvesAsAnAlias() {
    assertThat(ApprovedSchemas.forType("AdultStatusCredential")).containsExactly("adultOver18");
    assertThat(ApprovedSchemas.allows("AdultStatusCredential", "adultOver18")).isTrue();
  }

  @Test
  void unknownAndIncompatibleTypesAttestNothing() {
    assertThat(ApprovedSchemas.forType("https://sovra.example/vct/unknown/9")).isEmpty();
    assertThat(ApprovedSchemas.forType(ApprovedSchemas.EMPLOYMENT_VCT)).isEmpty();
    assertThat(ApprovedSchemas.forType(null)).isEmpty();
  }

  @Test
  void typeBindingRejectsCrossTypeSubstitution() {
    // Right claim, wrong type: a claim approved for one type never
    // authorizes another, even when one issuer attests both.
    assertThat(ApprovedSchemas.allows(SyntheticJwtEncoder.ADULT_VCT, "isAdult")).isFalse();
    assertThat(ApprovedSchemas.allows(ApprovedSchemas.FJORD_VCT, "adultOver18")).isFalse();
    assertThat(ApprovedSchemas.allows(ApprovedSchemas.FJORD_VCT, "isAdult")).isTrue();
    assertThat(ApprovedSchemas.allows(ApprovedSchemas.HARBOR_VCT, "qualifiesAsAdult")).isTrue();
  }

  @Test
  void employmentTenureCarriesANonAgeSemantic() {
    assertThat(ApprovedSchemas.semanticFor(
            ApprovedSchemas.EMPLOYMENT_VCT, "yearsInEmployment"))
        .contains("employment_tenure_years");
    assertThat(ApprovedSchemas.allows(
            ApprovedSchemas.EMPLOYMENT_VCT, "yearsInEmployment"))
        .isFalse();
    assertThat(ApprovedSchemas.semanticFor(
            SyntheticJwtEncoder.ADULT_VCT, "adultOver18"))
        .contains("age_over_18");
  }

  @Test
  void outcomeMapsToEveryApprovedSpelling() {
    assertThat(ApprovedSchemas.approvedClaimsForOutcome("age_over_18"))
        .containsExactlyInAnyOrder("adultOver18", "isAdult", "qualifiesAsAdult");
    assertThat(ApprovedSchemas.approvedClaimsForOutcome("age_over_21")).isEmpty();
    assertThat(ApprovedSchemas.approvedClaimsForOutcome(null)).isEmpty();
  }

  @Test
  void schemaDocumentsAreCitableEvidence() {
    Map<String, PolicyDocument> docs = ApprovedSchemas.documents();
    assertThat(docs).containsKeys(
        "sovra-schema/adult-status-v1",
        "sovra-schema/fjord-adult-v1",
        "sovra-schema/harbor-adult-v1",
        "sovra-schema/employment-tenure-v1");
    PolicyDocument fjord = docs.get("sovra-schema/fjord-adult-v1");
    assertThat(fjord.version()).isEqualTo("1");
    assertThat(fjord.sections()).containsKey("adult_eligibility");
  }

  @Test
  void canonicalClaimsKeepLegacyBytesIdentical() {
    assertThat(ApprovedSchemas.canonicalClaims(Map.of("adultOver18", Boolean.TRUE)))
        .isEqualTo("adultOver18=true");
    assertThat(ApprovedSchemas.canonicalClaims(Map.of("isAdult", Boolean.TRUE)))
        .isEqualTo("isAdult=true");
    assertThat(ApprovedSchemas.canonicalClaims(Map.of("qualifiesAsAdult", Boolean.TRUE)))
        .isEqualTo("qualifiesAsAdult=true");
  }

  @Test
  void canonicalClaimsSortAndRejectEmpties() {
    assertThat(ApprovedSchemas.canonicalClaims(Map.of("b", 1, "a", Boolean.TRUE)))
        .isEqualTo("a=true,b=1");
    assertThatThrownBy(() -> ApprovedSchemas.canonicalClaims(Map.of()))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> ApprovedSchemas.canonicalClaims(null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void guardClaimsDelegateToTheRegistry() {
    assertThat(GuardClaims.forType(SyntheticJwtEncoder.ADULT_VCT))
        .isEqualTo(ApprovedSchemas.forType(SyntheticJwtEncoder.ADULT_VCT));
    assertThat(GuardClaims.forType(ApprovedSchemas.FJORD_VCT)).containsExactly("isAdult");
  }

  @Test
  void legacyPolicyBudgetIsUnchangedAndMappedCoversAllSpellings() {
    PolicyDocument legacy = GuardPolicies.documents().get(GuardPolicies.POLICY_ID);
    assertThat(legacy.version()).isEqualTo("1");
    assertThat(legacy.approvedClaims()).containsExactly("adultOver18");
    PolicyDocument mapped = GuardPolicies.documents().get(GuardPolicies.MAPPED_POLICY_ID);
    assertThat(mapped.version()).isEqualTo("1");
    assertThat(mapped.approvedClaims())
        .containsExactly("adultOver18", "isAdult", "qualifiesAsAdult");
    assertThat(GuardPolicies.sectionFor(GuardPolicies.POLICY_ID, "1"))
        .isEqualTo(GuardPolicies.SECTION_ID);
    assertThat(GuardPolicies.sectionFor(GuardPolicies.MAPPED_POLICY_ID, "1"))
        .isEqualTo(GuardPolicies.MAPPED_SECTION_ID);
    assertThat(GuardPolicies.sectionFor("elsewhere", "1")).isNull();
  }

  @Test
  void guardRulesVersionIsTwo() {
    assertThat(PlanGuard.RULES_VERSION).isEqualTo("sovra-guard/2");
  }
}
