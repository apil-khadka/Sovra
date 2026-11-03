package dev.sovra.planning;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.guard.ApprovedSchemas;
import dev.sovra.guard.CandidatePlan;
import dev.sovra.guard.EvidenceCitation;
import dev.sovra.guard.GuardPolicies;
import dev.sovra.guard.PlanGuard;
import dev.sovra.guard.Recommendation;
import dev.sovra.issuance.DualIssuerFixtures;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.issuance.LocalDevSigner;
import dev.sovra.trust.IssuerStatus;
import dev.sovra.trust.TrustService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
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
 * Live-arm evaluator over corpus v2 (scoped discovery): injected/replayed
 * live-shaped results are scored against data-driven per-case expectations
 * with the REAL guard, the case's RP-selected policy, pinned snapshot,
 * explicit clock, and scope/expected binding — no provider call, no
 * {@code caseId} branches, no fake success. Fixture, null, and missing
 * injections clear completeness; suspended/expired issuers, fabricated
 * citations, policy mismatch, and wrong-case legacy plans all score
 * unexpected. Labels stay injected/replayed; proof execution stays
 * {@code NOT_EXECUTED}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class LiveArmEvaluatorTests extends SovraAppRoleBase {

  static final String CORPUS_DIR = "src/test/resources/planning-corpus-v2";

  /** Honest injected-model label: replayed shape, never a provider claim. */
  static final String REPLAY_MODEL = "injected-replay-test (no provider call)";

  @Autowired TrustService trust;

  @Autowired dev.sovra.trust.TrustSnapshotProvider snapshots;

  @Autowired PlanningEvaluator evaluator;

  @Autowired PlanningTools tools;

  @Autowired ObjectMapper mapper;

  JdbcTemplate owner;

  @BeforeEach
  void setup() throws Exception {
    owner = new JdbcTemplate(ownerDataSource());
    DualIssuerFixtures.ensureDualIssuers(owner, trust, mapper);
  }

  @SuppressWarnings("unchecked")
  private List<PlanningEvaluator.LiveEvalCase> corpus() throws Exception {
    List<PlanningEvaluator.LiveEvalCase> cases = new ArrayList<>();
    try (Stream<Path> files = Files.list(Path.of(CORPUS_DIR))) {
      for (Path file : files
          .filter(p -> p.getFileName().toString().startsWith("v2-")
              && p.toString().endsWith(".json"))
          .sorted()
          .toList()) {
        Map<String, Object> raw = mapper.readValue(Files.readString(file), Map.class);
        PlanningIntent intent = PlanningIntents.validate(
            raw.get("rpId").toString(),
            raw.get("audience").toString(),
            raw.get("purpose").toString(),
            raw.get("outcome").toString(),
            raw.get("policyId").toString(),
            raw.get("policyVersion").toString(),
            (List<String>) raw.get("requestedClaims"),
            (List<String>) raw.get("scopeIssuerIds"),
            (List<String>) raw.get("scopeCredentialTypes"),
            (List<String>) raw.get("scopeJurisdictions"));
        boolean expectCandidate = Boolean.parseBoolean(raw.get("expectCandidate").toString());
        PlanningEvaluator.ExpectedCandidate expected = null;
        if (expectCandidate) {
          expected = new PlanningEvaluator.ExpectedCandidate(
              raw.get("expectedIssuerId").toString(),
              raw.get("expectedCredentialType").toString(),
              (List<String>) raw.get("expectedClaimPaths"));
        }
        cases.add(
            new PlanningEvaluator.LiveEvalCase(
                raw.get("caseId").toString(),
                new BaselinePlanner.BaselineQuery(
                    raw.get("outcome").toString(),
                    raw.get("baselineIssuerId").toString(),
                    raw.get("baselineCredentialType").toString(),
                    (List<String>) raw.get("baselineRequestedClaims"),
                    raw.get("policyId").toString(),
                    raw.get("policyVersion").toString()),
                Recommendation.valueOf(raw.get("expectBaseline").toString()),
                intent,
                expectCandidate,
                expected,
                raw.get("note").toString()));
      }
    }
    cases.sort(Comparator.comparing(PlanningEvaluator.LiveEvalCase::caseId));
    return cases;
  }

  private PlanningResult replay(
      String caseId, Recommendation recommendation, CandidatePlan plan) {
    return PlanningResult.live(
        plan,
        recommendation,
        "injected/replayed " + caseId + " (no provider call)",
        REPLAY_MODEL,
        PlanningVersions.toolSchemaHash(tools.callbacks()),
        3,
        41L,
        500L);
  }

  private PlanningResult replayRefusal(String caseId, Recommendation recommendation) {
    return replay(caseId, recommendation, null);
  }

  private CandidatePlan candidate(
      String planId,
      String issuer,
      String type,
      String claim,
      String policyId,
      String section) {
    return new CandidatePlan(
        planId,
        "age_over_18",
        issuer,
        type,
        List.of(claim),
        List.of(new EvidenceCitation(policyId, section)),
        policyId,
        "1",
        Recommendation.CANDIDATE_ONLY);
  }

  private CandidatePlan knownPlan() {
    return candidate(
        "pln_replay_known",
        IssuanceFixtures.ISSUER_ID,
        IssuanceFixtures.ADULT_VCT,
        "adultOver18",
        GuardPolicies.POLICY_ID,
        GuardPolicies.SECTION_ID);
  }

  private CandidatePlan fjordPlan() {
    return candidate(
        "pln_replay_fjord",
        LocalDevSigner.SECOND_ISSUER_ID,
        ApprovedSchemas.FJORD_VCT,
        "isAdult",
        GuardPolicies.MAPPED_POLICY_ID,
        GuardPolicies.MAPPED_SECTION_ID);
  }

  private CandidatePlan harborPlan() {
    return candidate(
        "pln_replay_harbor",
        LocalDevSigner.SECOND_ISSUER_ID,
        ApprovedSchemas.HARBOR_VCT,
        "qualifiesAsAdult",
        GuardPolicies.MAPPED_POLICY_ID,
        GuardPolicies.MAPPED_SECTION_ID);
  }

  private PlanningEvaluator.LiveEvalCase byId(List<PlanningEvaluator.LiveEvalCase> corpus, String id) {
    return corpus.stream().filter(c -> c.caseId().equals(id)).findFirst().orElseThrow();
  }

  private PlanningEvaluator.LiveCaseResult liveById(
      List<PlanningEvaluator.LiveCaseResult> results, String id) {
    return results.stream().filter(r -> r.caseId().equals(id)).findFirst().orElseThrow();
  }

  @Test
  @SuppressWarnings("unchecked")
  void manifestFreezesFixturesAndConfiguration() throws Exception {
    Map<String, Object> manifest = mapper.readValue(
        Files.readString(Path.of(CORPUS_DIR).resolve("manifest.json")), Map.class);
    assertThat(manifest.get("corpusVersion")).isEqualTo(PlanningEvaluator.LIVE_CORPUS_VERSION);
    assertThat(manifest.get("promptVersion")).isEqualTo(PlanningVersions.PROMPT_VERSION);
    assertThat(manifest.get("toolContractVersion"))
        .isEqualTo(PlanningVersions.TOOL_CONTRACT_VERSION);
    assertThat(manifest.get("toolSchemaHash"))
        .isEqualTo(PlanningVersions.toolSchemaHash(tools.callbacks()));
    assertThat(manifest.get("baselineVersion")).isEqualTo(PlanningVersions.BASELINE_VERSION);
    assertThat(manifest.get("schemaRegistryVersion")).isEqualTo(ApprovedSchemas.version());
    assertThat(manifest.get("guardRulesVersion")).isEqualTo(PlanGuard.RULES_VERSION);
    Map<String, String> files = (Map<String, String>) manifest.get("files");
    MessageDigest sha = MessageDigest.getInstance("SHA-256");
    for (Map.Entry<String, String> entry : files.entrySet()) {
      byte[] bytes = Files.readAllBytes(Path.of(CORPUS_DIR).resolve(entry.getKey()));
      String digest = HexFormat.of().formatHex(sha.digest(bytes));
      assertThat(digest).as("digest of %s", entry.getKey()).isEqualTo(entry.getValue());
    }
    List<String> cases = (List<String>) manifest.get("cases");
    assertThat(cases).hasSize(5);
  }

  @Test
  void corpusCarriesFiveDataDrivenCasesWithDistinctIntents() throws Exception {
    List<PlanningEvaluator.LiveEvalCase> cases = corpus();
    assertThat(cases).hasSize(5);
    assertThat(cases.stream().map(PlanningEvaluator.LiveEvalCase::caseId).toList())
        .containsExactly(
            "V2-FJORD",
            "V2-HARBOR",
            "V2-KNOWN",
            "V2-TENURE",
            "V2-UNKNOWN-SCOPE");
    // Every live intent uses the canonical hint; the wire names under test
    // never leak into requestedClaims.
    for (PlanningEvaluator.LiveEvalCase eval : cases) {
      assertThat(eval.liveIntent().outcome()).isEqualTo("age_over_18");
      assertThat(eval.liveIntent().requestedClaims()).containsExactly("adultOver18");
    }
    // Scoped vs unscoped intents differ per case (no shared query).
    assertThat(byId(cases, "V2-KNOWN").liveIntent().scoped()).isFalse();
    assertThat(byId(cases, "V2-FJORD").liveIntent().scoped()).isTrue();
    assertThat(byId(cases, "V2-HARBOR").liveIntent().scoped()).isTrue();
    assertThat(byId(cases, "V2-TENURE").liveIntent().scoped()).isTrue();
    assertThat(byId(cases, "V2-UNKNOWN-SCOPE").liveIntent().scoped()).isTrue();
    // Data-driven expectations: three candidates, two refusals — the
    // scorer never branches on these ids.
    assertThat(byId(cases, "V2-KNOWN").expectCandidate()).isTrue();
    assertThat(byId(cases, "V2-FJORD").expectCandidate()).isTrue();
    assertThat(byId(cases, "V2-HARBOR").expectCandidate()).isTrue();
    assertThat(byId(cases, "V2-TENURE").expectCandidate()).isFalse();
    assertThat(byId(cases, "V2-UNKNOWN-SCOPE").expectCandidate()).isFalse();
  }

  @Test
  void injectedReplayScoresKnownBothUnfamiliarAndBothRefusals() throws Exception {
    var snapshot = snapshots.current().orElseThrow();
    List<PlanningEvaluator.LiveEvalCase> cases = corpus();
    Map<String, PlanningResult> live = new HashMap<>();
    live.put("V2-KNOWN", replay("V2-KNOWN", Recommendation.CANDIDATE_ONLY, knownPlan()));
    live.put("V2-FJORD", replay("V2-FJORD", Recommendation.CANDIDATE_ONLY, fjordPlan()));
    live.put("V2-HARBOR", replay("V2-HARBOR", Recommendation.CANDIDATE_ONLY, harborPlan()));
    live.put("V2-TENURE", replayRefusal("V2-TENURE", Recommendation.NO_PATH));
    live.put("V2-UNKNOWN-SCOPE", replayRefusal("V2-UNKNOWN-SCOPE", Recommendation.NO_PATH));

    PlanningEvaluator.LiveEvaluationReport report =
        evaluator.evaluateWithLive(snapshot, cases, live);

    assertThat(report.corpusVersion()).isEqualTo(PlanningEvaluator.LIVE_CORPUS_VERSION);
    assertThat(report.schemaRegistryVersion()).isEqualTo(ApprovedSchemas.version());
    assertThat(report.snapshotVersion()).isEqualTo(snapshot.version());
    assertThat(report.proofExecution()).isEqualTo(PlanningEvaluator.PROOF_NOT_EXECUTED);
    for (PlanningEvaluator.CaseResult base : report.baseline()) {
      assertThat(base.expected())
          .as("baseline %s: got %s (%s)", base.caseId(), base.recommendation(), base.reason())
          .isTrue();
    }
    for (PlanningEvaluator.LiveCaseResult result : report.live()) {
      assertThat(result.expected())
          .as("live %s: got %s (%s)", result.caseId(), result.recommendation(), result.reason())
          .isTrue();
      assertThat(result.provenance()).isEqualTo("injected-live-shaped");
      assertThat(result.model()).contains("injected-replay-test");
    }
    assertThat(liveById(report.live(), "V2-KNOWN").guardCode()).isEqualTo("GUARD_ACCEPTED");
    assertThat(liveById(report.live(), "V2-FJORD").guardCode()).isEqualTo("GUARD_ACCEPTED");
    assertThat(liveById(report.live(), "V2-HARBOR").guardCode()).isEqualTo("GUARD_ACCEPTED");
    assertThat(liveById(report.live(), "V2-TENURE").guardCode()).isEqualTo("NOT_APPLICABLE");
    assertThat(liveById(report.live(), "V2-UNKNOWN-SCOPE").guardCode()).isEqualTo("NOT_APPLICABLE");
    assertThat(report.complete()).isTrue();
    assertThat(report.allExpected()).isTrue();
    assertThat(report.agent().mode()).isEqualTo("LIVE");
    assertThat(report.agent().liveAcceptance()).isTrue();
    assertThat(report.agent().note()).contains("injected/replayed");
  }

  @Test
  void tenureCandidateScoresUnexpectedWithGuardCode() throws Exception {
    var snapshot = snapshots.current().orElseThrow();
    List<PlanningEvaluator.LiveEvalCase> cases =
        List.of(byId(corpus(), "V2-TENURE"));
    CandidatePlan tenure = candidate(
        "pln_replay_tenure",
        LocalDevSigner.SECOND_ISSUER_ID,
        ApprovedSchemas.EMPLOYMENT_VCT,
        "yearsInEmployment",
        GuardPolicies.MAPPED_POLICY_ID,
        GuardPolicies.MAPPED_SECTION_ID);
    PlanningEvaluator.LiveEvaluationReport report = evaluator.evaluateWithLive(
        snapshot, cases, Map.of(
            "V2-TENURE", replay("V2-TENURE", Recommendation.CANDIDATE_ONLY, tenure)));

    PlanningEvaluator.LiveCaseResult result = report.live().get(0);
    assertThat(result.expected()).isFalse();
    assertThat(result.provenance()).isEqualTo("injected-live-shaped");
    assertThat(result.guardCode())
        .isIn("GUARD_UNTRUSTED_CLAIM", "GUARD_UNSUPPORTED_OUTCOME");
    assertThat(report.complete()).isTrue();
    assertThat(report.allExpected()).isFalse();
  }

  @Test
  void unknownScopeValidatesWithout400AndRefusesAsNoPath() throws Exception {
    PlanningEvaluator.LiveEvalCase eval = byId(corpus(), "V2-UNKNOWN-SCOPE");
    // Well-formed unknown scope passes intent validation (no 400); the
    // narrowed plan step yields NO_PATH with no plan.
    var snapshot = snapshots.current().orElseThrow();
    PlanningResult fixture = FixturePlanner.plan(
        eval.liveIntent(), snapshot, java.time.Instant.now(),
        PlanningVersions.toolSchemaHash(tools.callbacks()));
    assertThat(fixture.recommendation()).isEqualTo(Recommendation.NO_PATH);
    assertThat(fixture.plan()).isNull();

    PlanningEvaluator.LiveEvaluationReport report = evaluator.evaluateWithLive(
        snapshot, List.of(eval),
        Map.of("V2-UNKNOWN-SCOPE",
            replayRefusal("V2-UNKNOWN-SCOPE", Recommendation.NO_PATH)));
    assertThat(report.live().get(0).expected()).isTrue();
    assertThat(report.live().get(0).guardCode()).isEqualTo("NOT_APPLICABLE");
  }

  @Test
  void suspendedIssuerCandidateScoresUnexpected() throws Exception {
    TrustService.SnapshotView liveSnapshot = snapshots.current().orElseThrow();
    TrustService.SnapshotView suspended = withStanding(
        liveSnapshot, IssuerStatus.SUSPENDED, null, null);
    PlanningEvaluator.LiveEvalCase eval = new PlanningEvaluator.LiveEvalCase(
        "V2-KNOWN",
        new BaselinePlanner.BaselineQuery(
            "age_over_18",
            IssuanceFixtures.ISSUER_ID,
            IssuanceFixtures.ADULT_VCT,
            List.of("adultOver18"),
            GuardPolicies.POLICY_ID,
            GuardPolicies.POLICY_VERSION),
        Recommendation.NO_PATH,
        byId(corpus(), "V2-KNOWN").liveIntent(),
        true,
        new PlanningEvaluator.ExpectedCandidate(
            IssuanceFixtures.ISSUER_ID, IssuanceFixtures.ADULT_VCT,
            List.of("adultOver18")),
        "suspended issuer standing probe");

    PlanningEvaluator.LiveEvaluationReport report = evaluator.evaluateWithLive(
        suspended, List.of(eval),
        Map.of("V2-KNOWN", replay("V2-KNOWN", Recommendation.CANDIDATE_ONLY, knownPlan())));

    PlanningEvaluator.LiveCaseResult result = report.live().get(0);
    assertThat(result.expected()).isFalse();
    assertThat(result.guardCode()).isEqualTo("GUARD_ISSUER_EPOCH_INVALID");
    assertThat(result.reason()).contains("GUARD_ISSUER_EPOCH_INVALID");
  }

  @Test
  void expiredIssuerCandidateScoresUnexpected() throws Exception {
    TrustService.SnapshotView liveSnapshot = snapshots.current().orElseThrow();
    java.time.Instant now = java.time.Instant.now();
    TrustService.SnapshotView expired = withStanding(
        liveSnapshot, IssuerStatus.ACTIVE, now.minusSeconds(7200), now.minusSeconds(3600));
    PlanningEvaluator.LiveEvalCase eval = new PlanningEvaluator.LiveEvalCase(
        "V2-KNOWN",
        new BaselinePlanner.BaselineQuery(
            "age_over_18",
            IssuanceFixtures.ISSUER_ID,
            IssuanceFixtures.ADULT_VCT,
            List.of("adultOver18"),
            GuardPolicies.POLICY_ID,
            GuardPolicies.POLICY_VERSION),
        Recommendation.NO_PATH,
        byId(corpus(), "V2-KNOWN").liveIntent(),
        true,
        new PlanningEvaluator.ExpectedCandidate(
            IssuanceFixtures.ISSUER_ID, IssuanceFixtures.ADULT_VCT,
            List.of("adultOver18")),
        "expired issuer epoch probe");

    PlanningEvaluator.LiveEvaluationReport report = evaluator.evaluateWithLive(
        expired, List.of(eval),
        Map.of("V2-KNOWN", replay("V2-KNOWN", Recommendation.CANDIDATE_ONLY, knownPlan())));

    PlanningEvaluator.LiveCaseResult result = report.live().get(0);
    assertThat(result.expected()).isFalse();
    assertThat(result.guardCode()).isEqualTo("GUARD_ISSUER_EPOCH_INVALID");
  }

  @Test
  void fabricatedCitationScoresUnexpected() throws Exception {
    var snapshot = snapshots.current().orElseThrow();
    PlanningEvaluator.LiveEvalCase eval = byId(corpus(), "V2-FJORD");
    CandidatePlan forged = new CandidatePlan(
        "pln_replay_forged",
        "age_over_18",
        LocalDevSigner.SECOND_ISSUER_ID,
        ApprovedSchemas.FJORD_VCT,
        List.of("isAdult"),
        List.of(new EvidenceCitation("invented-policy/doc", "invented-section")),
        GuardPolicies.MAPPED_POLICY_ID,
        GuardPolicies.MAPPED_POLICY_VERSION,
        Recommendation.CANDIDATE_ONLY);

    PlanningEvaluator.LiveEvaluationReport report = evaluator.evaluateWithLive(
        snapshot, List.of(eval),
        Map.of("V2-FJORD", replay("V2-FJORD", Recommendation.CANDIDATE_ONLY, forged)));

    PlanningEvaluator.LiveCaseResult result = report.live().get(0);
    assertThat(result.expected()).isFalse();
    assertThat(result.guardCode()).isIn("GUARD_UNKNOWN_POLICY", "GUARD_UNKNOWN_POLICY_SECTION");
  }

  @Test
  void selectedPolicyMismatchScoresUnexpected() throws Exception {
    var snapshot = snapshots.current().orElseThrow();
    PlanningEvaluator.LiveEvalCase eval = byId(corpus(), "V2-FJORD");
    // Fjord wire pair under the OLD policy: intent selects mapped, so the
    // real guard reports mismatch/overbroad — never acceptance.
    CandidatePlan mismatched = candidate(
        "pln_replay_mismatch",
        LocalDevSigner.SECOND_ISSUER_ID,
        ApprovedSchemas.FJORD_VCT,
        "isAdult",
        GuardPolicies.POLICY_ID,
        GuardPolicies.SECTION_ID);

    PlanningEvaluator.LiveEvaluationReport report = evaluator.evaluateWithLive(
        snapshot, List.of(eval),
        Map.of("V2-FJORD", replay("V2-FJORD", Recommendation.CANDIDATE_ONLY, mismatched)));

    PlanningEvaluator.LiveCaseResult result = report.live().get(0);
    assertThat(result.expected()).isFalse();
    assertThat(result.guardCode()).isEqualTo("GUARD_POLICY_MISMATCH");
  }

  @Test
  void inventedPolicyScoresUnexpected() throws Exception {
    var snapshot = snapshots.current().orElseThrow();
    PlanningEvaluator.LiveEvalCase eval = byId(corpus(), "V2-FJORD");
    CandidatePlan invented = new CandidatePlan(
        "pln_replay_invented",
        "age_over_18",
        LocalDevSigner.SECOND_ISSUER_ID,
        ApprovedSchemas.FJORD_VCT,
        List.of("isAdult"),
        List.of(new EvidenceCitation(
            GuardPolicies.MAPPED_POLICY_ID, GuardPolicies.MAPPED_SECTION_ID)),
        "sovra-synthetic-policy/invented",
        "1",
        Recommendation.CANDIDATE_ONLY);

    PlanningEvaluator.LiveEvaluationReport report = evaluator.evaluateWithLive(
        snapshot, List.of(eval),
        Map.of("V2-FJORD", replay("V2-FJORD", Recommendation.CANDIDATE_ONLY, invented)));

    assertThat(report.live().get(0).expected()).isFalse();
    assertThat(report.live().get(0).guardCode()).isEqualTo("GUARD_POLICY_MISMATCH");
  }

  @Test
  void wrongCaseLegacyPlanScoresUnexpectedForUnfamiliarScope() throws Exception {
    var snapshot = snapshots.current().orElseThrow();
    PlanningEvaluator.LiveEvalCase fjord = byId(corpus(), "V2-FJORD");
    // Guard-accepted in isolation under mapped policy (see
    // MappedGuardTests), but bound to the wrong case: synth-1 is outside
    // the fjord scope and the expected candidate names synth-2/fjord.
    CandidatePlan legacy = candidate(
        "pln_replay_legacy",
        IssuanceFixtures.ISSUER_ID,
        IssuanceFixtures.ADULT_VCT,
        "adultOver18",
        GuardPolicies.MAPPED_POLICY_ID,
        GuardPolicies.MAPPED_SECTION_ID);

    PlanningEvaluator.LiveEvaluationReport report = evaluator.evaluateWithLive(
        snapshot, List.of(fjord),
        Map.of("V2-FJORD", replay("V2-FJORD", Recommendation.CANDIDATE_ONLY, legacy)));

    PlanningEvaluator.LiveCaseResult result = report.live().get(0);
    assertThat(result.expected()).isFalse();
    assertThat(result.reason()).containsAnyOf(
        "outside the requested discovery scope", "but case expects");
  }

  @Test
  void missingInjectionClearsCompletenessAndAcceptance() throws Exception {
    var snapshot = snapshots.current().orElseThrow();
    List<PlanningEvaluator.LiveEvalCase> cases = corpus();
    Map<String, PlanningResult> live = new HashMap<>();
    live.put("V2-KNOWN", replay("V2-KNOWN", Recommendation.CANDIDATE_ONLY, knownPlan()));

    PlanningEvaluator.LiveEvaluationReport report =
        evaluator.evaluateWithLive(snapshot, cases, live);

    PlanningEvaluator.LiveCaseResult missing = liveById(report.live(), "V2-FJORD");
    assertThat(missing.recommendation()).isEqualTo("MISSING");
    assertThat(missing.expected()).isFalse();
    assertThat(missing.provenance()).isEqualTo("missing");
    assertThat(missing.guardCode()).isEqualTo("NOT_EVALUATED");
    assertThat(report.complete()).isFalse();
    assertThat(report.allExpected()).isFalse();
    assertThat(report.agent().liveAcceptance()).isFalse();
    assertThat(report.agent().note()).contains("injected/replayed");
  }

  @Test
  void nullResultsAndNullValueStayMissingNeverSuccess() throws Exception {
    var snapshot = snapshots.current().orElseThrow();
    List<PlanningEvaluator.LiveEvalCase> cases = List.of(byId(corpus(), "V2-KNOWN"));

    PlanningEvaluator.LiveEvaluationReport nullMap =
        evaluator.evaluateWithLive(snapshot, cases, null);
    assertThat(nullMap.live().get(0).recommendation()).isEqualTo("MISSING");
    assertThat(nullMap.live().get(0).provenance()).isEqualTo("missing");
    assertThat(nullMap.complete()).isFalse();
    assertThat(nullMap.agent().liveAcceptance()).isFalse();

    Map<String, PlanningResult> withNull = new HashMap<>();
    withNull.put("V2-KNOWN", null);
    PlanningEvaluator.LiveEvaluationReport nullValue =
        evaluator.evaluateWithLive(snapshot, cases, withNull);
    assertThat(nullValue.live().get(0).recommendation()).isEqualTo("NULL");
    assertThat(nullValue.live().get(0).provenance()).isEqualTo("null-injection");
    assertThat(nullValue.complete()).isFalse();
    assertThat(nullValue.agent().liveAcceptance()).isFalse();
  }

  @Test
  void fixtureInjectionIsRefusedRatherThanScored() throws Exception {
    var snapshot = snapshots.current().orElseThrow();
    List<PlanningEvaluator.LiveEvalCase> cases = List.of(byId(corpus(), "V2-KNOWN"));
    PlanningResult fixture = PlanningResult.fixture(
        knownPlan(), Recommendation.CANDIDATE_ONLY, "fixture attempt",
        PlanningVersions.toolSchemaHash(tools.callbacks()));

    PlanningEvaluator.LiveEvaluationReport report = evaluator.evaluateWithLive(
        snapshot, cases, Map.of("V2-KNOWN", fixture));

    assertThat(report.live()).hasSize(1);
    assertThat(report.live().get(0).expected()).isFalse();
    assertThat(report.live().get(0).provenance()).isEqualTo("injected-fixture");
    assertThat(report.live().get(0).reason()).contains("never satisfy live acceptance");
    assertThat(report.complete()).isFalse();
    assertThat(report.agent().liveAcceptance()).isFalse();
  }

  @Test
  void unavailableCaptureStaysMissingWithNoSilentSuccess() throws Exception {
    var snapshot = snapshots.current().orElseThrow();
    List<PlanningEvaluator.LiveEvalCase> cases = corpus();
    // A capture interrupted by provider 503/timeouts hands in no result
    // for the affected cases: empty map, same standing as missing.
    PlanningEvaluator.LiveEvaluationReport report =
        evaluator.evaluateWithLive(snapshot, cases, Map.of());

    assertThat(report.live()).hasSize(5);
    for (PlanningEvaluator.LiveCaseResult result : report.live()) {
      assertThat(result.recommendation()).isEqualTo("MISSING");
      assertThat(result.expected()).isFalse();
    }
    assertThat(report.complete()).isFalse();
    assertThat(report.allExpected()).isFalse();
    assertThat(report.agent().liveAcceptance()).isFalse();
  }

  private static TrustService.SnapshotView withStanding(
      TrustService.SnapshotView base,
      IssuerStatus status,
      java.time.Instant validFrom,
      java.time.Instant validThrough) {
    List<TrustService.IssuerView> issuers = new ArrayList<>();
    for (TrustService.IssuerView issuer : base.issuers()) {
      if (IssuanceFixtures.ISSUER_ID.equals(issuer.issuerId())) {
        issuers.add(
            new TrustService.IssuerView(
                issuer.issuerId(),
                issuer.displayName(),
                issuer.scope(),
                issuer.credentialTypes(),
                issuer.keyId(),
                issuer.keyVersion(),
                issuer.publicKeyJwk(),
                validFrom != null ? validFrom : issuer.validFrom(),
                validThrough != null ? validThrough : issuer.validThrough(),
                status));
      } else {
        issuers.add(issuer);
      }
    }
    return new TrustService.SnapshotView(base.version(), issuers, base.policies());
  }
}
