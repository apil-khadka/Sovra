package dev.sovra.guard;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.StringJoiner;
import java.util.regex.Pattern;

/**
 * Deterministic authorization guard (SOV-014), ported from the retired
 * TypeScript prototype with identical check order and outcome codes.
 * A candidate plan proposed by the AI planner is untrusted input; this
 * guard decides, with no model involvement, whether the plan may
 * proceed toward the holder wallet. Every rejection carries a stable
 * machine-readable code.
 *
 * <p>Validation order is fixed so failures are deterministic:
 * recommendation, shape, outcome semantics, issuer standing and scope,
 * RP policy binding, disclosure budget, citations.
 *
 * <p>Framework-independent: pure functions over records with explicit
 * version and clock inputs (NFR-06). No Spring, no storage, no ambient
 * time. JSON parsing lives in {@link PlanParser}.
 */
public final class PlanGuard {

  /** Guard rules version; carried in every verdict and audit row. */
  public static final String RULES_VERSION = "sovra-guard/1";

  /**
   * Frozen G1 outcome set (FR-06). Only age_over_18 has a trusted
   * issuer, claim allowlist, and policy binding behind it.
   */
  static final Set<String> SUPPORTED_OUTCOMES = Set.of("age_over_18");

  static final String CANONICAL_LABEL = "sovra-plan/v1";

  static final int MAX_STRING = 256;
  static final int MAX_CLAIMS = 32;
  static final int MAX_EVIDENCE = 32;

  /**
   * Safe identifier alphabet (SR-07): plan content is untrusted bounded
   * data, so every identifier and claim path must match before it can
   * name anything trusted. The alphabet excludes quoting, whitespace,
   * and the canonical-hash separators, which makes injection payloads
   * fail shape and canonicalization exact.
   */
  static final Pattern SAFE_TEXT = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}");

  private PlanGuard() {}

  /**
   * Validates a candidate plan against pinned trust and policy. Returns
   * {@code GUARD_ACCEPTED} only when every check passes; the wallet must
   * still obtain explicit holder consent before any presentation. The
   * disclosure budget comes only from the RP-selected policy, delivered
   * through trusted input alongside the plan: citations and
   * self-selected policies can never widen what the RP approved.
   */
  public static GuardVerdict validate(
      CandidatePlan plan, GuardContext context, SelectedPolicy selected, GuardInputs inputs) {
    if (plan == null || context == null || selected == null || inputs == null) {
      return GuardVerdict.reject(GuardOutcome.GUARD_MALFORMED_PLAN, "Guard input is missing.");
    }
    if (!RULES_VERSION.equals(inputs.rulesVersion()) || inputs.now() == null) {
      return GuardVerdict.reject(
          GuardOutcome.GUARD_MALFORMED_PLAN, "Guard rules version or clock is not supported.");
    }
    if (plan.recommendation() != Recommendation.CANDIDATE_ONLY) {
      return GuardVerdict.reject(
          GuardOutcome.MANUAL_REVIEW, "Planner reports no executable path; a human must review.");
    }
    GuardVerdict shape = checkShape(plan);
    if (shape != null) {
      return shape;
    }
    if (!SUPPORTED_OUTCOMES.contains(plan.requestedOutcome())) {
      return GuardVerdict.reject(
          GuardOutcome.GUARD_UNSUPPORTED_OUTCOME,
          "Requested outcome '" + plan.requestedOutcome() + "' has no trusted G1 mapping.");
    }
    TrustedIssuer issuer = context.trustedIssuers().get(plan.candidateIssuerId());
    if (issuer == null) {
      return GuardVerdict.reject(
          GuardOutcome.GUARD_UNKNOWN_ISSUER,
          "Issuer '" + plan.candidateIssuerId() + "' is not in the pinned trust set.");
    }
    GuardVerdict standing = checkStanding(issuer, inputs);
    if (standing != null) {
      return standing;
    }
    if (!issuer.allowedCredentialTypes().contains(plan.credentialType())) {
      return GuardVerdict.reject(
          GuardOutcome.GUARD_UNTRUSTED_CREDENTIAL_TYPE,
          "Credential type '" + plan.credentialType() + "' is outside issuer scope.");
    }
    if (!safe(selected.policyId()) || !safe(selected.policyVersion())) {
      return GuardVerdict.reject(
          GuardOutcome.GUARD_MALFORMED_PLAN, "Selected policy binding is malformed.");
    }
    if (!plan.policyId().equals(selected.policyId())
        || !plan.policyVersion().equals(selected.policyVersion())) {
      return GuardVerdict.reject(
          GuardOutcome.GUARD_POLICY_MISMATCH,
          "Plan policy '" + plan.policyId() + "' version '" + plan.policyVersion()
              + "' does not match the RP-selected policy.");
    }
    PolicyDocument trusted = context.policies().get(selected.policyId());
    if (trusted == null || !trusted.version().equals(selected.policyVersion())) {
      return GuardVerdict.reject(
          GuardOutcome.GUARD_UNKNOWN_POLICY,
          "Selected policy '" + selected.policyId() + "' version '" + selected.policyVersion()
              + "' is not a known versioned policy.");
    }
    GuardVerdict budget = checkDisclosureBudget(plan, issuer, trusted.approvedClaims());
    if (budget != null) {
      return budget;
    }
    GuardVerdict citations = checkCitations(plan, context);
    if (citations != null) {
      return citations;
    }
    return GuardVerdict.accept();
  }

  private static GuardVerdict checkShape(CandidatePlan plan) {
    if (!safe(plan.planId())
        || !safe(plan.requestedOutcome())
        || !safe(plan.candidateIssuerId())
        || !safe(plan.credentialType())
        || !safe(plan.policyId())
        || !safe(plan.policyVersion())
        || plan.claimPaths() == null
        || plan.claimPaths().isEmpty()
        || plan.claimPaths().size() > MAX_CLAIMS
        || plan.evidence() == null
        || plan.evidence().size() > MAX_EVIDENCE) {
      return GuardVerdict.reject(
          GuardOutcome.GUARD_MALFORMED_PLAN,
          "Plan is missing required fields or exceeds guard bounds.");
    }
    for (String claim : plan.claimPaths()) {
      if (!safe(claim)) {
        return GuardVerdict.reject(
            GuardOutcome.GUARD_MALFORMED_PLAN, "Plan carries an unsafe or empty claim path.");
      }
    }
    for (EvidenceCitation citation : plan.evidence()) {
      if (citation == null || !safe(citation.documentId()) || !safe(citation.sectionId())) {
        return GuardVerdict.reject(
            GuardOutcome.GUARD_MISSING_CITATION,
            "Every claimed mapping must cite a document and section.");
      }
    }
    return null;
  }

  private static GuardVerdict checkStanding(TrustedIssuer issuer, GuardInputs inputs) {
    if (!"ACTIVE".equals(issuer.status())
        || issuer.validFrom() == null
        || issuer.validThrough() == null
        || issuer.validFrom().isAfter(inputs.now())
        || issuer.validThrough().isBefore(inputs.now())) {
      return GuardVerdict.reject(
          GuardOutcome.GUARD_ISSUER_EPOCH_INVALID,
          "Issuer '" + issuer.issuerId() + "' is not currently authorized.");
    }
    return null;
  }

  private static GuardVerdict checkDisclosureBudget(
      CandidatePlan plan, TrustedIssuer issuer, List<String> policyClaims) {
    for (String claim : plan.claimPaths()) {
      if (!issuer.allowedClaims().contains(claim)) {
        return GuardVerdict.reject(
            GuardOutcome.GUARD_UNTRUSTED_CLAIM,
            "Claim '" + claim + "' is outside the issuer's trusted attestation scope.");
      }
      if (!policyClaims.contains(claim)) {
        return GuardVerdict.reject(
            GuardOutcome.GUARD_OVERBROAD_DISCLOSURE,
            "Claim '" + claim + "' exceeds the relying party's approved disclosure budget.");
      }
    }
    return null;
  }

  private static GuardVerdict checkCitations(CandidatePlan plan, GuardContext context) {
    if (plan.evidence().isEmpty()) {
      return GuardVerdict.reject(
          GuardOutcome.GUARD_MISSING_CITATION,
          "Plan carries no source citations for its claimed mapping.");
    }
    for (EvidenceCitation citation : plan.evidence()) {
      PolicyDocument policy = context.policies().get(citation.documentId());
      if (policy == null) {
        return GuardVerdict.reject(
            GuardOutcome.GUARD_UNKNOWN_POLICY,
            "Cited policy '" + citation.documentId() + "' is not a known versioned document.");
      }
      if (!policy.sections().containsKey(citation.sectionId())) {
        return GuardVerdict.reject(
            GuardOutcome.GUARD_UNKNOWN_POLICY_SECTION,
            "Section '" + citation.sectionId() + "' does not exist in '"
                + citation.documentId() + "'.");
      }
    }
    return null;
  }

  private static boolean safe(String value) {
    return value != null && value.length() <= MAX_STRING && SAFE_TEXT.matcher(value).matches();
  }

  /**
   * Canonical plan hash: SHA-256 hex over the fixed-order plan form.
   * Consent binds this hash, so the wallet reviews exactly the plan the
   * guard accepted. The safe alphabet excludes the separators, so the
   * form is unambiguous without escaping.
   */
  public static String canonicalHash(CandidatePlan plan) {
    StringJoiner claims = new StringJoiner(",");
    for (String claim : plan.claimPaths()) {
      claims.add(claim);
    }
    StringJoiner evidence = new StringJoiner(",");
    for (EvidenceCitation citation : plan.evidence()) {
      evidence.add(citation.documentId() + "#" + citation.sectionId());
    }
    String canonical =
        CANONICAL_LABEL + "\n" + plan.planId() + "\n" + plan.requestedOutcome() + "\n"
            + plan.candidateIssuerId() + "\n" + plan.credentialType() + "\n" + claims + "\n"
            + evidence + "\n" + plan.policyId() + "\n" + plan.policyVersion() + "\n"
            + plan.recommendation().name() + "\n";
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }
}
