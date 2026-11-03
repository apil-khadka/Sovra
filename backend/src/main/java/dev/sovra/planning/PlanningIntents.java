package dev.sovra.planning;

import dev.sovra.guard.ApprovedSchemas;
import java.util.List;
import java.util.Set;

/**
 * Intent validation ahead of any model contact (SOV-013, FR-04, SR-07).
 * G1 freezes exactly one semantic outcome with registry-approved wire
 * spellings and two approved RP policy bindings (legacy plus mapped);
 * anything else is an invalid intent, not a planning question. Bounds
 * keep prompts finite (NFR-03). Policy-budget enforcement stays in the
 * guard: an old-policy intent naming a mapped-only alias passes here
 * and fails there with OVERBROAD, which is the correct authority.
 */
public final class PlanningIntents {

  static final int MAX_ID_CHARS = 512;
  static final int MAX_CLAIMS = 8;

  static final String OUTCOME = "age_over_18";

  static final Set<String> KNOWN_CLAIMS =
      Set.copyOf(ApprovedSchemas.approvedClaimsForOutcome(OUTCOME));

  private PlanningIntents() {}

  /** Validates the raw intent; throws before any model call on failure. */
  public static PlanningIntent validate(
      String rpId,
      String audience,
      String purpose,
      String outcome,
      String policyId,
      String policyVersion,
      List<String> requestedClaims) {
    return validate(
        rpId, audience, purpose, outcome, policyId, policyVersion, requestedClaims,
        null, null, null);
  }

  /**
   * Validates the raw intent with optional discovery scope. Scope shape is
   * bounded here (list sizes, string lengths); scope VALUES are untrusted
   * hints resolved against approved metadata at planning time — unknown
   * values yield NO_PATH then, never a 400 here.
   */
  public static PlanningIntent validate(
      String rpId,
      String audience,
      String purpose,
      String outcome,
      String policyId,
      String policyVersion,
      List<String> requestedClaims,
      List<String> scopeIssuerIds,
      List<String> scopeCredentialTypes,
      List<String> scopeJurisdictions) {
    requireBounded(rpId, "rpId");
    requireBounded(audience, "audience");
    requireBounded(purpose, "purpose");
    if (!OUTCOME.equals(outcome)) {
      throw new InvalidPlanningException("unsupported planning outcome");
    }
    if (!PlanningPrompts.approvedPolicy(policyId, policyVersion)) {
      throw new InvalidPlanningException("unknown policy binding");
    }
    if (requestedClaims == null
        || requestedClaims.isEmpty()
        || requestedClaims.size() > MAX_CLAIMS) {
      throw new InvalidPlanningException("requested claims are missing or excessive");
    }
    for (String claim : requestedClaims) {
      if (claim == null || !KNOWN_CLAIMS.contains(claim)) {
        throw new InvalidPlanningException("unsupported requested claim");
      }
    }
    // Every requested wire name must be a registry-approved spelling of
    // the requested semantic outcome; the guard additionally binds each
    // wire pair to its exact credential type and the selected policy.
    if (!ApprovedSchemas.approvedClaimsForOutcome(outcome).containsAll(requestedClaims)) {
      throw new InvalidPlanningException("requested claims exceed the approved registry");
    }
    return new PlanningIntent(
        rpId, audience, purpose, outcome, policyId, policyVersion, List.copyOf(requestedClaims),
        scopeList(scopeIssuerIds, "scopeIssuerIds"),
        scopeList(scopeCredentialTypes, "scopeCredentialTypes"),
        scopeList(scopeJurisdictions, "scopeJurisdictions"));
  }

  /** Bounds one scope list; null means unscoped. Values stay untrusted hints. */
  private static List<String> scopeList(List<String> values, String field) {
    if (values == null || values.isEmpty()) {
      return List.of();
    }
    if (values.size() > MAX_CLAIMS) {
      throw new InvalidPlanningException(field + " is excessive");
    }
    for (String value : values) {
      if (value == null || value.isBlank() || value.length() > MAX_ID_CHARS) {
        throw new InvalidPlanningException(field + " carries a malformed hint");
      }
    }
    return List.copyOf(values);
  }

  private static void requireBounded(String value, String field) {
    if (value == null || value.isBlank() || value.length() > MAX_ID_CHARS) {
      throw new InvalidPlanningException(field + " is missing or exceeds its bound");
    }
  }
}
