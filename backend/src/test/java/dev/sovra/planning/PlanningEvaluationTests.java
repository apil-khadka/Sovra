package dev.sovra.planning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.guard.CandidatePlan;
import dev.sovra.guard.EvidenceCitation;
import dev.sovra.guard.GuardPolicies;
import dev.sovra.guard.Recommendation;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustSnapshotProvider;
import dev.sovra.trust.TrustService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.ObjectMapper;

/**
 * Frozen-corpus evaluation (SOV-013, FR-11, AC-05, NFR-10): the
 * deterministic baseline resolves the known case, refuses incompatible
 * and adversarial cases without inventing paths, and the harness
 * refuses to score fixture agent output as live evidence.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class PlanningEvaluationTests extends SovraAppRoleBase {

  /** Corpus version; any fixture change renames the corpus, never edits. */
  static final String CORPUS_VERSION = "sovra-planning-corpus/1";

  static final int EXPECTED_CASES = 8;

  @Autowired TrustService trust;

  @Autowired TrustSnapshotProvider snapshots;

  @Autowired PlanningEvaluator evaluator;

  @Autowired PlanningService planning;

  @Autowired PlanningTools tools;

  @Autowired ObjectMapper mapper;

  JdbcTemplate owner;

  @BeforeEach
  void setup() throws Exception {
    owner = new JdbcTemplate(ownerDataSource());
    IssuanceFixtures.ensureSyntheticIssuer(owner, trust, mapper);
  }

  @SuppressWarnings("unchecked")
  private List<PlanningEvaluator.EvalCase> corpus() throws Exception {
    Path dir = Path.of("src/test/resources/planning-corpus");
    List<PlanningEvaluator.EvalCase> cases = new ArrayList<>();
    try (Stream<Path> files = Files.list(dir)) {
      for (Path file : files.filter(p -> p.toString().endsWith(".json")).sorted().toList()) {
        Map<String, Object> raw = mapper.readValue(Files.readString(file), Map.class);
        cases.add(
            new PlanningEvaluator.EvalCase(
                raw.get("caseId").toString(),
                new BaselinePlanner.BaselineQuery(
                    raw.get("outcome").toString(),
                    raw.get("issuerId").toString(),
                    raw.get("credentialType").toString(),
                    (List<String>) raw.get("requestedClaims"),
                    raw.get("policyId").toString(),
                    raw.get("policyVersion").toString()),
                Recommendation.valueOf(raw.get("expectBaseline").toString()),
                raw.get("note").toString()));
      }
    }
    cases.sort(Comparator.comparing(PlanningEvaluator.EvalCase::caseId));
    return cases;
  }

  @Test
  void baselineMatchesEveryFrozenExpectation() throws Exception {
    List<PlanningEvaluator.EvalCase> cases = corpus();
    assertThat(cases).hasSize(EXPECTED_CASES);

    var snapshot = snapshots.current().orElseThrow();
    PlanningEvaluator.EvaluationReport report = evaluator.evaluate(snapshot, cases);

    assertThat(report.promptVersion()).isEqualTo(PlanningVersions.PROMPT_VERSION);
    assertThat(report.toolContractVersion()).isEqualTo(PlanningVersions.TOOL_CONTRACT_VERSION);
    assertThat(report.toolSchemaHash())
        .isEqualTo(PlanningVersions.toolSchemaHash(tools.callbacks()));
    assertThat(report.baselineVersion()).isEqualTo(PlanningVersions.BASELINE_VERSION);
    for (PlanningEvaluator.CaseResult result : report.baseline()) {
      assertThat(result.expected())
          .as("baseline case %s: got %s (%s)", result.caseId(), result.recommendation(),
              result.reason())
          .isTrue();
    }
    // The comparison is meaningful only with both arms present: at
    // least one compatible resolution and one incompatible refusal.
    assertThat(report.baseline().stream().map(PlanningEvaluator.CaseResult::recommendation))
        .contains("CANDIDATE_ONLY", "NO_PATH", "MANUAL_REVIEW");
  }

  @Test
  void unseenCompatibleCaseRefusesWithoutAnAdapter() throws Exception {
    var snapshot = snapshots.current().orElseThrow();
    PlanningEvaluator.EvaluationReport report = evaluator.evaluate(snapshot, corpus());
    PlanningEvaluator.CaseResult u1 =
        report.baseline().stream()
            .filter(r -> r.caseId().equals("U1"))
            .findFirst()
            .orElseThrow();
    // The exact-match engine cannot adapt to the unseen schema; a live
    // agent beating this proves discovery, not a fixture branch.
    assertThat(u1.recommendation()).isEqualTo("NO_PATH");
    assertThat(u1.expected()).isTrue();
  }

  @Test
  void agentArmRecordsFixtureStandingHonestly() throws Exception {
    var snapshot = snapshots.current().orElseThrow();
    PlanningEvaluator.EvaluationReport report = evaluator.evaluate(snapshot, corpus());

    assertThat(report.agent().mode()).isEqualTo("FIXTURE");
    assertThat(report.agent().liveAcceptance()).isFalse();
  }

  @Test
  void fixtureResultsNeverSatisfyLiveAcceptance() {
    var snapshot = snapshots.current().orElseThrow();
    PlanningResult fixture =
        FixturePlanner.plan(
            PlanningIntents.validate(
                "https://rp.example/synth-shop",
                "https://rp.example/synth-shop/callback",
                "synthetic age check",
                "age_over_18",
                dev.sovra.guard.GuardPolicies.POLICY_ID,
                dev.sovra.guard.GuardPolicies.POLICY_VERSION,
                List.of("adultOver18")),
            snapshot,
            java.time.Instant.now(),
            PlanningVersions.toolSchemaHash(tools.callbacks()));

    assertThat(fixture.liveAcceptance()).isFalse();
    assertThatThrownBy(() -> planning.requireLive(fixture))
        .isInstanceOf(InvalidPlanningException.class);
    assertThatThrownBy(() -> evaluator.scoreLive(fixture))
        .isInstanceOf(InvalidPlanningException.class);
    assertThatThrownBy(() -> planning.requireLive(null))
        .isInstanceOf(InvalidPlanningException.class);
  }

  @Test
  void liveShapedResultsSatisfyLiveAcceptance() {
    // The evaluator live arm (scoreLive path) makes no provider call:
    // it accepts exactly the live shape LivePlanner returns and the
    // OD-02 smoke verifies over HTTP (mode LIVE, liveAcceptance true).
    String toolHash = PlanningVersions.toolSchemaHash(tools.callbacks());
    var plan =
        new CandidatePlan(
            "pln_live_shape_001",
            "age_over_18",
            IssuanceFixtures.ISSUER_ID,
            IssuanceFixtures.ADULT_VCT,
            List.of("adultOver18"),
            List.of(new EvidenceCitation(GuardPolicies.POLICY_ID, GuardPolicies.SECTION_ID)),
            GuardPolicies.POLICY_ID,
            GuardPolicies.POLICY_VERSION,
            Recommendation.CANDIDATE_ONLY);
    PlanningResult live =
        PlanningResult.live(
            plan,
            Recommendation.CANDIDATE_ONLY,
            "live-shaped harness result",
            "test-only-live-model",
            toolHash,
            5,
            12671L,
            10853L);

    assertThat(live.liveAcceptance()).isTrue();
    assertThat(live.mode()).isEqualTo(PlanningMode.LIVE);
    assertThat(planning.requireLive(live)).isSameAs(live);
    assertThat(evaluator.scoreLive(live)).isSameAs(live);
  }
}
