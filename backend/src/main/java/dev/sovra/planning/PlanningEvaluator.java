package dev.sovra.planning;

import dev.sovra.guard.GuardContexts;
import dev.sovra.guard.GuardInputs;
import dev.sovra.guard.GuardVerdict;
import dev.sovra.guard.PlanGuard;
import dev.sovra.guard.Recommendation;
import dev.sovra.guard.SelectedPolicy;
import dev.sovra.trust.TrustService;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

/**
 * Frozen-corpus evaluation (SOV-013, FR-11, NFR-10): the deterministic
 * baseline arm runs over compatible, incompatible, and adversarial
 * cases with recorded expectations, and the agent arm reports its
 * provenance honestly. In fixture mode the agent arm is recorded as
 * not-live and refused live scoring — fixture runs never satisfy live
 * acceptance, however the baseline scores.
 *
 * <p>Live scoring ({@link #evaluateWithLive}) reuses the ACTUAL
 * deterministic {@link PlanGuard} with the SAME trusted context
 * construction production uses ({@link GuardContexts#fromSnapshot}),
 * the case's RP-selected policy, the pinned snapshot, and the explicit
 * evaluator clock. It maintains no weaker parallel authorization: issuer
 * standing/epochs, per-type claim binding, semantic-outcome binding,
 * policy budgets, and citation grounding all adjudicate exactly as the
 * served guard. Scope binding reuses {@link PlanningService#bindToScope}
 * semantics via the case intent, so a guard-valid legacy answer for an
 * unfamiliar scoped case still scores unexpected.
 *
 * <p>Live expectations are data-driven per case ({@link LiveEvalCase}),
 * never {@code caseId} branches. Injected {@code LIVE}-shaped values are
 * scored as injected/replayed evidence only: passing the shape gate
 * ({@code requireLive}) never establishes actual provider execution,
 * which requires an authenticated server capture with retained
 * provenance (see {@code docs/ai/planner-evaluation.md}). Proof
 * execution stays {@code NOT_EXECUTED} here; candidates are not proofs.
 */
@Service
public class PlanningEvaluator {

  /** Versioned live corpus scored by {@link #evaluateWithLive}. */
  public static final String LIVE_CORPUS_VERSION = "sovra-planning-corpus/2";

  /**
   * Proof-execution standing for this scorer: candidates are scored
   * against the guard, never executed as proofs. Stays
   * {@code NOT_EXECUTED} unless separate verification receipts are
   * provided and checked elsewhere.
   */
  public static final String PROOF_NOT_EXECUTED = "NOT_EXECUTED";

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

  /** Exact candidate a live case expects when it expects a path. */
  public record ExpectedCandidate(
      String issuerId,
      String credentialType,
      List<String> claimPaths) {}

  /**
   * One data-driven live case: the baseline query plus its expectation
   * (reference arm), the live intent (RP-selected policy, outcome,
   * canonical hint claims, flat discovery scopes), whether live must
   * produce a guard-accepted candidate bound to this case, and the exact
   * expected issuer/type/claims when it must. No {@code caseId} carries
   * meaning to the scorer; every expectation travels with the case.
   */
  public record LiveEvalCase(
      String caseId,
      BaselinePlanner.BaselineQuery baselineQuery,
      Recommendation expectBaseline,
      PlanningIntent liveIntent,
      boolean expectCandidate,
      ExpectedCandidate expectedCandidate,
      String note) {
    public LiveEvalCase {
      if (liveIntent == null || baselineQuery == null) {
        throw new IllegalArgumentException("live case carries no intent");
      }
      if (expectCandidate && expectedCandidate == null) {
        throw new IllegalArgumentException("candidate case names no expected plan");
      }
      if (!expectCandidate && expectedCandidate != null) {
        throw new IllegalArgumentException("refusal case must not name a candidate");
      }
      if (expectedCandidate != null) {
        expectedCandidate = new ExpectedCandidate(
            expectedCandidate.issuerId(),
            expectedCandidate.credentialType(),
            List.copyOf(expectedCandidate.claimPaths()));
      }
    }
  }

  /**
   * One scored live case: the injected result plus its live expectation.
   * {@code provenance} is one of {@code injected-live-shaped},
   * {@code injected-fixture}, {@code missing}, or {@code null-injection};
   * only the first passes the shape gate, and even it proves shape only,
   * never actual provider execution. {@code guardCode} is the real
   * {@link PlanGuard} outcome for a scored plan, {@code NOT_APPLICABLE}
   * for a correct refusal with no plan, or {@code NOT_EVALUATED} when no
   * live-shaped plan existed to adjudicate.
   */
  public record LiveCaseResult(
      String caseId,
      String recommendation,
      boolean expected,
      String reason,
      String model,
      int toolCalls,
      long latencyMs,
      String provenance,
      String guardCode) {}

  /**
   * Live evaluation report: baseline reference arm plus scored
   * injected/replayed live arm. {@code complete} is true only when every
   * case had a live-shaped injection passing {@code requireLive} (no
   * missing, null, or fixture values). {@code allExpected} is true only
   * when every live case matched its data-driven expectation.
   * {@code proofExecution} stays {@code NOT_EXECUTED}: guard acceptance
   * of a candidate never claims a proof ran.
   */
  public record LiveEvaluationReport(
      String promptVersion,
      String toolContractVersion,
      String toolSchemaHash,
      String baselineVersion,
      String schemaRegistryVersion,
      List<CaseResult> baseline,
      List<LiveCaseResult> live,
      AgentArm agent,
      String corpusVersion,
      long snapshotVersion,
      boolean complete,
      boolean allExpected,
      String proofExecution) {}

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

  /**
   * Scores INJECTED/REPLAYED live-shaped results against data-driven
   * per-case expectations without calling any provider. Each value must
   * already be live-shaped (mode LIVE, liveAcceptance true) — typically
   * captured from an authenticated run elsewhere and handed in for
   * scoring; fixture values, nulls, and missing entries are recorded as
   * such, never scored as live evidence, and clear the report's
   * {@code complete} and agent {@code liveAcceptance} flags.
   *
   * <p>For a case expecting a candidate, the injection must be
   * {@code CANDIDATE_ONLY} with a non-null plan whose outcome equals the
   * case outcome, whose issuer/type/claims equal the case's expected
   * candidate, which sits inside the case's discovery scope (via the
   * shared scope binding), and which the REAL {@link PlanGuard} accepts
   * under the case's RP-selected policy with the pinned snapshot and
   * explicit clock. A guard-valid legacy plan for an unfamiliar scoped
   * case fails scope/expected binding and scores unexpected. For a case
   * expecting refusal, the injection must be {@code NO_PATH} or
   * {@code MANUAL_REVIEW} with a null plan; any {@code CANDIDATE_ONLY}
   * (or refusal carrying a plan) scores unexpected, with the guard code
   * retained for diagnostics when a plan exists.
   */
  public LiveEvaluationReport evaluateWithLive(
      TrustService.SnapshotView snapshot,
      List<LiveEvalCase> corpus,
      Map<String, PlanningResult> liveResults) {
    String toolHash = PlanningVersions.toolSchemaHash(tools.callbacks());
    List<CaseResult> baseline = new ArrayList<>();
    for (LiveEvalCase eval : corpus) {
      long started = clock.millis();
      BaselinePlanner.BaselineResult outcome =
          BaselinePlanner.plan(eval.baselineQuery(), snapshot, clock.instant());
      long latency = Math.max(0, clock.millis() - started);
      baseline.add(
          new CaseResult(
              eval.caseId(),
              outcome.recommendation().name(),
              outcome.recommendation() == eval.expectBaseline(),
              outcome.reason(),
              latency));
    }
    List<LiveCaseResult> scored = new ArrayList<>();
    int shaped = 0;
    for (LiveEvalCase eval : corpus) {
      PlanningResult live = liveResults == null ? null : liveResults.get(eval.caseId());
      if (liveResults == null || !liveResults.containsKey(eval.caseId()) || live == null) {
        boolean nullValue = liveResults != null
            && liveResults.containsKey(eval.caseId())
            && live == null;
        scored.add(new LiveCaseResult(
            eval.caseId(),
            nullValue ? "NULL" : "MISSING",
            false,
            nullValue
                ? "injected result is null; unavailable captures stay missing, never success"
                : "no injected live result; unavailable captures stay missing, never success",
            "none",
            0,
            0L,
            nullValue ? "null-injection" : "missing",
            "NOT_EVALUATED"));
        continue;
      }
      PlanningResult accepted;
      try {
        accepted = planning.requireLive(live);
      } catch (RuntimeException e) {
        scored.add(new LiveCaseResult(
            eval.caseId(),
            live.recommendation() == null ? "NULL" : live.recommendation().name(),
            false,
            "rejected: fixture results never satisfy live acceptance",
            live.model() == null ? "none" : live.model(),
            live.toolCalls(),
            live.latencyMs(),
            "injected-fixture",
            "NOT_EVALUATED"));
        continue;
      }
      shaped++;
      scored.add(scoreShaped(snapshot, eval, accepted));
    }
    boolean complete = !corpus.isEmpty() && shaped == corpus.size();
    boolean allExpected = !scored.isEmpty() && scored.stream().allMatch(LiveCaseResult::expected);
    long expectedCount = scored.stream().filter(LiveCaseResult::expected).count();
    AgentArm arm = new AgentArm(
        PlanningMode.LIVE.name(),
        complete,
        "injected/replayed live-shaped results scored without a provider call"
            + " (" + shaped + "/" + corpus.size() + " live-shaped, "
            + expectedCount + "/" + scored.size() + " expected);"
            + " shape acceptance only, not proof of provider execution;"
            + " proof execution " + PROOF_NOT_EXECUTED);
    return new LiveEvaluationReport(
        PlanningVersions.PROMPT_VERSION,
        PlanningVersions.TOOL_CONTRACT_VERSION,
        toolHash,
        PlanningVersions.BASELINE_VERSION,
        dev.sovra.guard.ApprovedSchemas.version(),
        List.copyOf(baseline),
        List.copyOf(scored),
        arm,
        LIVE_CORPUS_VERSION,
        snapshot.version(),
        complete,
        allExpected,
        PROOF_NOT_EXECUTED);
  }

  private LiveCaseResult scoreShaped(
      TrustService.SnapshotView snapshot, LiveEvalCase eval, PlanningResult accepted) {
    String model = accepted.model() == null ? "none" : accepted.model();
    if (!eval.expectCandidate()) {
      return scoreRefusal(snapshot, eval, accepted, model);
    }
    return scoreCandidate(snapshot, eval, accepted, model);
  }

  private LiveCaseResult scoreRefusal(
      TrustService.SnapshotView snapshot, LiveEvalCase eval, PlanningResult accepted, String model) {
    if (accepted.recommendation() == Recommendation.CANDIDATE_ONLY || accepted.plan() != null) {
      String guardCode = "NOT_EVALUATED";
      String detail = "refusal case must be NO_PATH or MANUAL_REVIEW with no plan";
      if (accepted.plan() != null) {
        GuardVerdict verdict = guard(snapshot, eval, accepted.plan());
        guardCode = verdict.code().name();
        detail += "; injected plan guards as " + guardCode;
      }
      return new LiveCaseResult(
          eval.caseId(), accepted.recommendation().name(), false, detail,
          model, accepted.toolCalls(), accepted.latencyMs(),
          "injected-live-shaped", guardCode);
    }
    return new LiveCaseResult(
        eval.caseId(), accepted.recommendation().name(), true, accepted.reason(),
        model, accepted.toolCalls(), accepted.latencyMs(),
        "injected-live-shaped", "NOT_APPLICABLE");
  }

  private LiveCaseResult scoreCandidate(
      TrustService.SnapshotView snapshot, LiveEvalCase eval, PlanningResult accepted, String model) {
    if (accepted.recommendation() != Recommendation.CANDIDATE_ONLY || accepted.plan() == null) {
      return new LiveCaseResult(
          eval.caseId(),
          accepted.recommendation() == null ? "NULL" : accepted.recommendation().name(),
          false,
          "candidate case must be CANDIDATE_ONLY with a plan",
          model, accepted.toolCalls(), accepted.latencyMs(),
          "injected-live-shaped", "NOT_EVALUATED");
    }
    var plan = accepted.plan();
    if (!eval.liveIntent().outcome().equals(plan.requestedOutcome())) {
      return unexpected(
          eval, accepted, model, "NOT_EVALUATED",
          "plan outcome '" + plan.requestedOutcome()
              + "' does not match case outcome '" + eval.liveIntent().outcome() + "'");
    }
    PlanningResult bound = PlanningService.bindToScope(accepted, eval.liveIntent(), snapshot);
    if (bound.recommendation() != Recommendation.CANDIDATE_ONLY || bound.plan() == null) {
      return unexpected(
          eval, accepted, model, "NOT_EVALUATED",
          "candidate is outside the requested discovery scope");
    }
    ExpectedCandidate want = eval.expectedCandidate();
    if (!want.issuerId().equals(plan.candidateIssuerId())
        || !want.credentialType().equals(plan.credentialType())
        || !want.claimPaths().equals(plan.claimPaths())) {
      return unexpected(
          eval, accepted, model, "NOT_EVALUATED",
          "plan names " + plan.candidateIssuerId() + " " + plan.credentialType()
              + " " + plan.claimPaths() + " but case expects " + want.issuerId()
              + " " + want.credentialType() + " " + want.claimPaths());
    }
    GuardVerdict verdict = guard(snapshot, eval, plan);
    if (!verdict.accepted()) {
      return unexpected(
          eval, accepted, model, verdict.code().name(),
          "real guard rejects injected plan with " + verdict.code().name()
              + (verdict.reason() == null ? "" : ": " + verdict.reason()));
    }
    return new LiveCaseResult(
        eval.caseId(), accepted.recommendation().name(), true, accepted.reason(),
        model, accepted.toolCalls(), accepted.latencyMs(),
        "injected-live-shaped", verdict.code().name());
  }

  private LiveCaseResult unexpected(
      LiveEvalCase eval, PlanningResult accepted, String model, String guardCode, String reason) {
    return new LiveCaseResult(
        eval.caseId(), accepted.recommendation().name(), false, reason,
        model, accepted.toolCalls(), accepted.latencyMs(),
        "injected-live-shaped", guardCode);
  }

  /** Real guard adjudication under the case's RP-selected policy. */
  private GuardVerdict guard(
      TrustService.SnapshotView snapshot, LiveEvalCase eval, dev.sovra.guard.CandidatePlan plan) {
    return PlanGuard.validate(
        plan,
        GuardContexts.fromSnapshot(snapshot),
        new SelectedPolicy(eval.liveIntent().policyId(), eval.liveIntent().policyVersion()),
        new GuardInputs(PlanGuard.RULES_VERSION, clock.instant()));
  }

  private AgentArm fixtureAgentArm() {
    return new AgentArm(
        PlanningMode.FIXTURE.name(),
        false,
        "agent runs use the labeled fixture planner until a verified"
            + " no-charge live run exists; fixture output is not live evidence");
  }
}
