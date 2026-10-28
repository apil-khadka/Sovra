package dev.sovra.planning;

import dev.sovra.guard.Recommendation;
import dev.sovra.trust.TrustService;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Service;

/**
 * Frozen-corpus evaluation (SOV-013, FR-11, NFR-10): the deterministic
 * baseline arm runs over compatible, incompatible, and adversarial
 * cases with recorded expectations, and the agent arm reports its
 * provenance honestly. In fixture mode the agent arm is recorded as
 * not-live and refused live scoring — fixture runs never satisfy live
 * acceptance, however the baseline scores.
 */
@Service
public class PlanningEvaluator {

  private final PlanningService planning;
  private final PlanningTools tools;
  private final Clock clock;

  public PlanningEvaluator(PlanningService planning, PlanningTools tools, Clock clock) {
    this.planning = planning;
    this.tools = tools;
    this.clock = clock;
  }

  /** One frozen case: inputs plus the baseline's expected recommendation. */
  public record EvalCase(
      String caseId,
      BaselinePlanner.BaselineQuery query,
      Recommendation expectBaseline,
      String note) {}

  public record CaseResult(
      String caseId,
      String recommendation,
      boolean expected,
      String reason,
      long latencyMs) {}

  public record AgentArm(String mode, boolean liveAcceptance, String note) {}

  public record EvaluationReport(
      String promptVersion,
      String toolContractVersion,
      String toolSchemaHash,
      String baselineVersion,
      List<CaseResult> baseline,
      AgentArm agent) {}

  /** Runs the baseline arm and records the agent arm's live standing. */
  public EvaluationReport evaluate(TrustService.SnapshotView snapshot, List<EvalCase> corpus) {
    String toolHash = PlanningVersions.toolSchemaHash(tools.callbacks());
    List<CaseResult> results = new ArrayList<>();
    for (EvalCase eval : corpus) {
      long started = clock.millis();
      BaselinePlanner.BaselineResult outcome =
          BaselinePlanner.plan(eval.query(), snapshot, clock.instant());
      long latency = Math.max(0, clock.millis() - started);
      results.add(
          new CaseResult(
              eval.caseId(),
              outcome.recommendation().name(),
              outcome.recommendation() == eval.expectBaseline(),
              outcome.reason(),
              latency));
    }
    return new EvaluationReport(
        PlanningVersions.PROMPT_VERSION,
        PlanningVersions.TOOL_CONTRACT_VERSION,
        toolHash,
        PlanningVersions.BASELINE_VERSION,
        List.copyOf(results),
        fixtureAgentArm());
  }

  /**
   * Scores one agent result as live evidence, refusing fixture mode.
   * The baseline comparison is complete without it; live scoring waits
   * for a verified no-charge live run (OD-02).
   */
  public PlanningResult scoreLive(PlanningResult agentResult) {
    return planning.requireLive(agentResult);
  }

  private AgentArm fixtureAgentArm() {
    return new AgentArm(
        PlanningMode.FIXTURE.name(),
        false,
        "agent runs use the labeled fixture planner until a verified"
            + " no-charge live run exists; fixture output is not live evidence");
  }
}
