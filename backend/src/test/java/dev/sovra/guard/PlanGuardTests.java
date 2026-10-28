package dev.sovra.guard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Deterministic guard decisions (SOV-014, FR-06, NFR-06, NFR-10).
 * Pure domain tests over the frozen corpus in {@code tests/fixtures}:
 * no Spring, no storage, explicit rules version and clock on every
 * call. Each file in the corpus is executed; anything unlisted here is
 * an uncovered fixture, not a pass.
 */
class PlanGuardTests {

  /** Fixed guard clock inside the corpus validity windows. */
  static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");

  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static final GuardInputs INPUTS = new GuardInputs(PlanGuard.RULES_VERSION, NOW);
  private static final SelectedPolicy SELECTED =
      new SelectedPolicy("rp-au-demo-v1", "1");

  private static Path corpus() {
    Path root = Path.of(System.getProperty("user.dir")).resolve("../tests/fixtures").normalize();
    if (!Files.isDirectory(root)) {
      throw new IllegalStateException("frozen guard corpus is missing: " + root);
    }
    return root;
  }

  private static JsonNode fixture(String name) throws Exception {
    return MAPPER.readTree(Files.readString(corpus().resolve(name)));
  }

  private static GuardVerdict decide(String plan, String context) throws Exception {
    return PlanGuard.validate(
        PlanParser.parsePlan(fixture(plan)),
        PlanParser.parseContext(fixture(context)),
        SELECTED,
        INPUTS);
  }

  @Test
  void validPlanIsAccepted() throws Exception {
    GuardVerdict verdict = decide("plan-valid.json", "trust-context.json");
    assertThat(verdict.accepted()).isTrue();
    assertThat(verdict.code()).isEqualTo(GuardOutcome.GUARD_ACCEPTED);
  }

  @Test
  void unknownIssuerRejects() throws Exception {
    GuardVerdict verdict = decide("plan-unknown-issuer.json", "trust-context.json");
    assertThat(verdict.accepted()).isFalse();
    assertThat(verdict.code()).isEqualTo(GuardOutcome.GUARD_UNKNOWN_ISSUER);
  }

  @Test
  void untrustedClaimRejects() throws Exception {
    GuardVerdict verdict = decide("plan-untrusted-claim.json", "trust-context.json");
    assertThat(verdict.accepted()).isFalse();
    assertThat(verdict.code()).isEqualTo(GuardOutcome.GUARD_UNTRUSTED_CLAIM);
  }

  @Test
  void overbroadDisclosureRejects() throws Exception {
    GuardVerdict verdict = decide("plan-overbroad.json", "trust-context.json");
    assertThat(verdict.accepted()).isFalse();
    assertThat(verdict.code()).isEqualTo(GuardOutcome.GUARD_OVERBROAD_DISCLOSURE);
  }

  @Test
  void fabricatedCitationRejects() throws Exception {
    GuardVerdict verdict = decide("plan-fabricated-citation.json", "trust-context.json");
    assertThat(verdict.accepted()).isFalse();
    assertThat(verdict.code()).isEqualTo(GuardOutcome.GUARD_UNKNOWN_POLICY_SECTION);
  }

  @Test
  void noPathRoutesToManualReview() throws Exception {
    GuardVerdict verdict = decide("plan-no-path.json", "trust-context.json");
    assertThat(verdict.accepted()).isFalse();
    assertThat(verdict.code()).isEqualTo(GuardOutcome.MANUAL_REVIEW);
  }

  @Test
  void unknownPolicyVersionRejects() throws Exception {
    CandidatePlan plan = PlanParser.parsePlan(fixture("plan-valid.json"));
    CandidatePlan relabeled =
        new CandidatePlan(
            plan.planId(), plan.requestedOutcome(), plan.candidateIssuerId(),
            plan.credentialType(), plan.claimPaths(), plan.evidence(), plan.policyId(), "99",
            plan.recommendation());
    GuardVerdict verdict =
        PlanGuard.validate(
            relabeled,
            PlanParser.parseContext(fixture("trust-context.json")),
            new SelectedPolicy("rp-au-demo-v1", "99"),
            INPUTS);
    assertThat(verdict.accepted()).isFalse();
    assertThat(verdict.code()).isEqualTo(GuardOutcome.GUARD_UNKNOWN_POLICY);
  }

  @Test
  void substitutedBroaderPolicyRejects() throws Exception {
    CandidatePlan overbroad = PlanParser.parsePlan(fixture("plan-overbroad.json"));
    CandidatePlan substituted =
        new CandidatePlan(
            overbroad.planId(), overbroad.requestedOutcome(), overbroad.candidateIssuerId(),
            overbroad.credentialType(), overbroad.claimPaths(), overbroad.evidence(),
            "rp-broad-v1", "1", overbroad.recommendation());
    GuardVerdict verdict =
        PlanGuard.validate(
            substituted, PlanParser.parseContext(fixture("trust-context.json")), SELECTED, INPUTS);
    assertThat(verdict.accepted()).isFalse();
    assertThat(verdict.code()).isEqualTo(GuardOutcome.GUARD_POLICY_MISMATCH);
  }

  @Test
  void emptyClaimPathsRejectAsMalformed() throws Exception {
    CandidatePlan plan = PlanParser.parsePlan(fixture("plan-valid.json"));
    CandidatePlan malformed =
        new CandidatePlan(
            plan.planId(), plan.requestedOutcome(), plan.candidateIssuerId(),
            plan.credentialType(), List.of(), plan.evidence(), plan.policyId(),
            plan.policyVersion(), plan.recommendation());
    GuardVerdict verdict =
        PlanGuard.validate(
            malformed, PlanParser.parseContext(fixture("trust-context.json")), SELECTED, INPUTS);
    assertThat(verdict.accepted()).isFalse();
    assertThat(verdict.code()).isEqualTo(GuardOutcome.GUARD_MALFORMED_PLAN);
  }

  @Test
  void unsupportedOutcomeRejects() throws Exception {
    GuardVerdict verdict = decide("plan-unsupported-outcome.json", "trust-context.json");
    assertThat(verdict.accepted()).isFalse();
    assertThat(verdict.code()).isEqualTo(GuardOutcome.GUARD_UNSUPPORTED_OUTCOME);
  }

  @Test
  void injectedClaimFailsShape() throws Exception {
    // The injection payload never matches a trusted value: unsafe
    // characters fail the shape check before any authority is named.
    GuardVerdict verdict = decide("plan-injection.json", "trust-context.json");
    assertThat(verdict.accepted()).isFalse();
    assertThat(verdict.code()).isEqualTo(GuardOutcome.GUARD_MALFORMED_PLAN);
  }

  @Test
  void incompatibleSchemaFailsParsing() throws Exception {
    assertThatThrownBy(() -> PlanParser.parsePlan(fixture("plan-incompatible-schema.json")))
        .isInstanceOf(MalformedPlanException.class);
  }

  @Test
  void suspendedIssuerRejects() throws Exception {
    GuardVerdict verdict = decide("plan-suspended-issuer.json", "trust-context-epoch.json");
    assertThat(verdict.accepted()).isFalse();
    assertThat(verdict.code()).isEqualTo(GuardOutcome.GUARD_ISSUER_EPOCH_INVALID);
  }

  @Test
  void expiredIssuerRejects() throws Exception {
    GuardVerdict verdict = decide("plan-expired-issuer.json", "trust-context-epoch.json");
    assertThat(verdict.accepted()).isFalse();
    assertThat(verdict.code()).isEqualTo(GuardOutcome.GUARD_ISSUER_EPOCH_INVALID);
  }

  @Test
  void epochWindowIsInclusiveAtTheBoundary() throws Exception {
    // The expired-issuer window ends 2021-01-01T00:00:00Z; evaluated
    // exactly there, standing holds and the cited plan accepts.
    GuardInputs boundary =
        new GuardInputs(PlanGuard.RULES_VERSION, Instant.parse("2021-01-01T00:00:00Z"));
    GuardVerdict verdict =
        PlanGuard.validate(
            PlanParser.parsePlan(fixture("plan-expired-issuer.json")),
            PlanParser.parseContext(fixture("trust-context-epoch.json")),
            SELECTED,
            boundary);
    assertThat(verdict.accepted()).isTrue();
    assertThat(verdict.code()).isEqualTo(GuardOutcome.GUARD_ACCEPTED);
  }

  @Test
  void unknownRulesVersionRejects() throws Exception {
    GuardVerdict verdict =
        PlanGuard.validate(
            PlanParser.parsePlan(fixture("plan-valid.json")),
            PlanParser.parseContext(fixture("trust-context.json")),
            SELECTED,
            new GuardInputs("sovra-guard/99", NOW));
    assertThat(verdict.accepted()).isFalse();
    assertThat(verdict.code()).isEqualTo(GuardOutcome.GUARD_MALFORMED_PLAN);
  }

  @Test
  void missingInputsReject() {
    assertThat(
            PlanGuard.validate(null, null, SELECTED, INPUTS).code())
        .isEqualTo(GuardOutcome.GUARD_MALFORMED_PLAN);
  }

  @Test
  void canonicalHashMatchesTheGoldenValue() throws Exception {
    CandidatePlan plan = PlanParser.parsePlan(fixture("plan-valid.json"));
    // Independently computed with SHA-256 over the fixed-order form;
    // consent binds this exact value, so any drift breaks approval.
    assertThat(PlanGuard.canonicalHash(plan))
        .isEqualTo("1b48dea5d62a496e9371598000e27c0051175c7b30234a5305f171abb4937d16");
  }

  @Test
  void canonicalHashIsOrderSensitive() throws Exception {
    CandidatePlan plan = PlanParser.parsePlan(fixture("plan-valid.json"));
    CandidatePlan reordered =
        new CandidatePlan(
            plan.planId(), plan.requestedOutcome(), plan.candidateIssuerId(),
            plan.credentialType(), List.of("adultOver18", "birthYear"), plan.evidence(),
            plan.policyId(), plan.policyVersion(), plan.recommendation());
    CandidatePlan swapped =
        new CandidatePlan(
            plan.planId(), plan.requestedOutcome(), plan.candidateIssuerId(),
            plan.credentialType(), List.of("birthYear", "adultOver18"), plan.evidence(),
            plan.policyId(), plan.policyVersion(), plan.recommendation());
    assertThat(PlanGuard.canonicalHash(reordered))
        .isNotEqualTo(PlanGuard.canonicalHash(swapped));
  }
}
