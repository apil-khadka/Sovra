package dev.sovra.planning;

import dev.sovra.guard.ApprovedSchemas;
import dev.sovra.guard.CandidatePlan;
import dev.sovra.guard.EvidenceCitation;
import dev.sovra.guard.GuardPolicies;
import dev.sovra.guard.Recommendation;
import dev.sovra.trust.IssuerKeys;
import dev.sovra.trust.TrustService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Explicitly-labeled fixture planner for offline development (SOV-013).
 * Produces a deterministic registry-driven candidate without contacting any
 * model; every result carries {@code mode=FIXTURE} and
 * {@code liveAcceptance=false}. Fixture output proves wire-shape
 * compatibility with the guard only — it never satisfies live
 * acceptance ({@link PlanningService#requireLive} enforces this).
 * Selection is generic over the shared registry, never a fixture-specific
 * type-name branch.
 */
public final class FixturePlanner {

  static final String MODEL_LABEL = "none (fixture)";

  private FixturePlanner() {}

  public static PlanningResult plan(
      PlanningIntent intent, TrustService.SnapshotView snapshot, Instant now, String toolHash) {
    record Pick(TrustService.IssuerView issuer, String type, List<String> claims) {}
    Pick pick = null;
    outer:
    for (TrustService.IssuerView issuer : snapshot.issuers()) {
      if (!IssuerKeys.usable(issuer, now)) {
        continue;
      }
      if (!intent.scopeIssuerIds().isEmpty()
          && !intent.scopeIssuerIds().contains(issuer.issuerId())) {
        continue;
      }
      if (!intent.scopeJurisdictions().isEmpty()
          && intent.scopeJurisdictions().stream()
              .noneMatch(hint -> issuer.scope() != null && issuer.scope().contains(hint))) {
        continue;
      }
      for (String type : issuer.credentialTypes()) {
        if (!intent.scopeCredentialTypes().isEmpty()
            && !intent.scopeCredentialTypes().contains(type)) {
          continue;
        }
        List<String> attestable = ApprovedSchemas.forType(type);
        if (attestable.isEmpty()) {
          continue;
        }
        boolean semantic = attestable.stream()
            .anyMatch(c -> intent.outcome().equals(
                ApprovedSchemas.semanticFor(type, c).orElse(null)));
        if (!semantic) {
          continue;
        }
        pick = new Pick(issuer, type, attestable);
        break outer;
      }
    }
    if (pick == null) {
      return PlanningResult.fixture(
          null, Recommendation.NO_PATH, "no usable issuer attests the requested semantic",
          toolHash);
    }
    String section =
        GuardPolicies.sectionFor(intent.policyId(), intent.policyVersion());
    if (section == null) {
      return PlanningResult.fixture(
          null, Recommendation.NO_PATH, "intent policy binding is not approved", toolHash);
    }
    CandidatePlan plan =
        new CandidatePlan(
            "pln_fixture_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12),
            intent.outcome(),
            pick.issuer().issuerId(),
            pick.type(),
            List.copyOf(pick.claims()),
            List.of(new EvidenceCitation(intent.policyId(), section)),
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
