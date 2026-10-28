package dev.sovra.planning;

import dev.sovra.guard.GuardClaims;
import dev.sovra.issuance.SyntheticJwtEncoder;
import java.util.List;
import java.util.Set;

/**
 * Intent validation ahead of any model contact (SOV-013, FR-04, SR-07).
 * G1 freezes exactly one outcome, one credential type with one claim,
 * and one policy document; anything else is an invalid intent, not a
 * planning question. Bounds keep prompts finite (NFR-03).
 */
public final class PlanningIntents {

  static final int MAX_ID_CHARS = 512;
  static final int MAX_CLAIMS = 8;

  static final String OUTCOME = "age_over_18";

  static final Set<String> KNOWN_CLAIMS = Set.of("adultOver18");

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
    // G1 allows exactly the adult-status claim on the adult-status type;
    // GuardClaims is the single allowlist both planner and guard share.
    if (!GuardClaims.forType(SyntheticJwtEncoder.ADULT_VCT).containsAll(requestedClaims)) {
      throw new InvalidPlanningException("requested claims exceed the G1 allowlist");
    }
    return new PlanningIntent(
        rpId, audience, purpose, outcome, policyId, policyVersion, List.copyOf(requestedClaims));
  }

  private static void requireBounded(String value, String field) {
    if (value == null || value.isBlank() || value.length() > MAX_ID_CHARS) {
      throw new InvalidPlanningException(field + " is missing or exceeds its bound");
    }
  }
}
