package dev.sovra.planning;

import dev.sovra.guard.CandidatePlan;
import dev.sovra.guard.EvidenceCitation;
import dev.sovra.guard.GuardPolicies;
import dev.sovra.guard.Recommendation;
import dev.sovra.issuance.SyntheticJwtEncoder;
import dev.sovra.trust.TrustService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Explicitly-labeled fixture planner for offline development (SOV-013).
 * Produces the deterministic known-G1 candidate without contacting any
 * model; every result carries {@code mode=FIXTURE} and
 * {@code liveAcceptance=false}. Fixture output proves wire-shape
 * compatibility with the guard only — it never satisfies live
 * acceptance ({@link PlanningService#requireLive} enforces this).
 */
public final class FixturePlanner {

  static final String MODEL_LABEL = "none (fixture)";

  private FixturePlanner() {}

  public static PlanningResult plan(
      PlanningIntent intent, TrustService.SnapshotView snapshot, Instant now, String toolHash) {
    TrustService.IssuerView issuer =
        snapshot.issuers().stream()
            .filter(i -> PlanningIssuers.usable(i, now))
            .filter(i -> i.credentialTypes().contains(SyntheticJwtEncoder.ADULT_VCT))
            .findFirst()
            .orElse(null);
    if (issuer == null) {
      return PlanningResult.fixture(
          null, Recommendation.NO_PATH, "no usable issuer attests the G1 claim", toolHash);
    }
    CandidatePlan plan =
        new CandidatePlan(
            "pln_fixture_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12),
            intent.outcome(),
            issuer.issuerId(),
            SyntheticJwtEncoder.ADULT_VCT,
            List.copyOf(intent.requestedClaims()),
            List.of(new EvidenceCitation(GuardPolicies.POLICY_ID, GuardPolicies.SECTION_ID)),
            intent.policyId(),
            intent.policyVersion(),
            Recommendation.CANDIDATE_ONLY);
    return PlanningResult.fixture(
        plan, Recommendation.CANDIDATE_ONLY, "deterministic fixture candidate", toolHash);
  }

  /**
   * Snake-case wire rendering shared by live and fixture results; shape
   * mirrors the guard's accepted plan form exactly.
   */
  public static Map<String, Object> wire(CandidatePlan plan) {
    return Map.of(
        "plan_id", plan.planId(),
        "requested_outcome", plan.requestedOutcome(),
        "candidate_issuer_id", plan.candidateIssuerId(),
        "credential_type", plan.credentialType(),
        "claim_paths", plan.claimPaths(),
        "evidence",
            plan.evidence().stream()
                .map(c -> Map.of("document_id", c.documentId(), "section_id", c.sectionId()))
                .toList(),
        "policy_id", plan.policyId(),
        "policy_version", plan.policyVersion(),
        "recommendation", plan.recommendation().name());
  }
}
