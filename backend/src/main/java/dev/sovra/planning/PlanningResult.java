package dev.sovra.planning;

import dev.sovra.guard.CandidatePlan;
import dev.sovra.guard.Recommendation;

/**
 * One planning outcome with its provenance (SOV-013, FR-05, NFR-10).
 * {@code liveAcceptance} is true only for results produced by a real
 * model call; fixture results always carry false, and the evaluation
 * harness refuses to score them as live evidence.
 */
public record PlanningResult(
    PlanningMode mode,
    boolean liveAcceptance,
    boolean synthetic,
    String profile,
    CandidatePlan plan,
    Recommendation recommendation,
    String reason,
    String model,
    String promptVersion,
    String toolContractVersion,
    String toolSchemaHash,
    int toolCalls,
    long latencyMs,
    Long usageTokens,
    String cost) {

  static PlanningResult fixture(
      CandidatePlan plan, Recommendation recommendation, String reason, String toolHash) {
    return new PlanningResult(
        PlanningMode.FIXTURE,
        false,
        true,
        PlanningVersions.PROFILE,
        plan,
        recommendation,
        reason,
        FixturePlanner.MODEL_LABEL,
        PlanningVersions.PROMPT_VERSION,
        PlanningVersions.TOOL_CONTRACT_VERSION,
        toolHash,
        0,
        0,
        null,
        "unreported");
  }

  static PlanningResult live(
      CandidatePlan plan,
      Recommendation recommendation,
      String reason,
      String model,
      String toolHash,
      int toolCalls,
      long latencyMs,
      Long usageTokens) {
    return new PlanningResult(
        PlanningMode.LIVE,
        true,
        true,
        PlanningVersions.PROFILE,
        plan,
        recommendation,
        reason,
        model,
        PlanningVersions.PROMPT_VERSION,
        PlanningVersions.TOOL_CONTRACT_VERSION,
        toolHash,
        toolCalls,
        latencyMs,
        usageTokens,
        "unreported");
  }
}
