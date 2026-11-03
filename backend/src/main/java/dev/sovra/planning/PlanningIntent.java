package dev.sovra.planning;

import java.util.List;

/**
 * Validated planning intent (SOV-013, FR-04). The service validates
 * purpose, outcome, RP identity, and the approved policy binding
 * before any model call; invalid or spoofed intents fail without
 * contacting the provider.
 *
 * <p>The optional discovery scope narrows which approved metadata the
 * planner may consider (untrusted RP hints: exact issuer ids, exact
 * credential types, jurisdiction substrings). Empty lists mean unscoped
 * (legacy behavior, byte-identical prompts). Scope only narrows — it
 * never grants authority: unknown scope values yield NO_PATH at planning
 * time, never a 400 and never invented metadata.
 */
public record PlanningIntent(
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

  /** True when the caller narrowed discovery at all. */
  public boolean scoped() {
    return !scopeIssuerIds.isEmpty()
        || !scopeCredentialTypes.isEmpty()
        || !scopeJurisdictions.isEmpty();
  }
}
