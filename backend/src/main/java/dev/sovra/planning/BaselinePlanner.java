package dev.sovra.planning;

import dev.sovra.guard.CandidatePlan;
import dev.sovra.guard.EvidenceCitation;
import dev.sovra.guard.GuardClaims;
import dev.sovra.guard.GuardPolicies;
import dev.sovra.guard.Recommendation;
import dev.sovra.issuance.SyntheticJwtEncoder;
import dev.sovra.trust.TrustService;
import java.time.Instant;
import java.util.List;

/**
 * Deterministic exact-match baseline (SOV-013, FR-11): the fixed
 * {@code AdultStatusCredential.adultOver18} mapping with no unseen-schema
 * adaptation and no model. The evaluation harness compares live-agent
 * coverage against this engine on the same frozen corpus; the baseline
 * never consults fixture-specific adapters.
 */
public final class BaselinePlanner {

  private BaselinePlanner() {}

  /** Query over pinned registry metadata; mirrors the evaluation corpus. */
  public record BaselineQuery(
      String outcome,
      String issuerId,
      String credentialType,
      List<String> requestedClaims,
      String policyId,
      String policyVersion) {}

  public record BaselineResult(
      Recommendation recommendation, CandidatePlan plan, String reason) {}

  /**
   * Exact-match planning over the active snapshot. Unknown outcomes,
   * issuers, types, claims, or policies resolve to MANUAL_REVIEW or
   * NO_PATH — never to an invented executable path.
   */
  public static BaselineResult plan(
      BaselineQuery query, TrustService.SnapshotView snapshot, Instant now) {
    if (!PlanningIntents.OUTCOME.equals(query.outcome())) {
      return review(null, "unsupported outcome");
    }
    if (!PlanningPrompts.approvedPolicy(query.policyId(), query.policyVersion())) {
      return review(null, "unknown policy binding");
    }
    TrustService.IssuerView issuer =
        snapshot.issuers().stream()
            .filter(i -> query.issuerId().equals(i.issuerId()))
            .findFirst()
            .orElse(null);
    if (issuer == null) {
      return noPath("issuer is not pinned registry metadata");
    }
    if (!PlanningIssuers.usable(issuer, now)) {
      return noPath("issuer is not currently usable");
    }
    if (!issuer.credentialTypes().contains(query.credentialType())
        || !SyntheticJwtEncoder.ADULT_VCT.equals(query.credentialType())) {
      return review(null, "credential type is outside the fixed mapping");
    }
    List<String> allowed = GuardClaims.forType(query.credentialType());
    if (query.requestedClaims() == null
        || query.requestedClaims().isEmpty()
        || !allowed.containsAll(query.requestedClaims())) {
      return noPath("requested claims exceed the fixed mapping");
    }
    CandidatePlan plan =
        new CandidatePlan(
            "pln_baseline_exact",
            query.outcome(),
            issuer.issuerId(),
            query.credentialType(),
            List.copyOf(query.requestedClaims()),
            List.of(new EvidenceCitation(GuardPolicies.POLICY_ID, GuardPolicies.SECTION_ID)),
            query.policyId(),
            query.policyVersion(),
            Recommendation.CANDIDATE_ONLY);
    return new BaselineResult(Recommendation.CANDIDATE_ONLY, plan, "exact fixed mapping");
  }

  private static BaselineResult noPath(String reason) {
    return new BaselineResult(Recommendation.NO_PATH, null, reason);
  }

  private static BaselineResult review(CandidatePlan plan, String reason) {
    return new BaselineResult(Recommendation.MANUAL_REVIEW, plan, reason);
  }
}
