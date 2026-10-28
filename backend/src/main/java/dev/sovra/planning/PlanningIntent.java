package dev.sovra.planning;

import java.util.List;

/**
 * Validated planning intent (SOV-013, FR-04). The service validates
 * purpose, outcome, RP identity, and the approved policy binding
 * before any model call; invalid or spoofed intents fail without
 * contacting the provider.
 */
public record PlanningIntent(
    String rpId,
    String audience,
    String purpose,
    String outcome,
    String policyId,
    String policyVersion,
    List<String> requestedClaims) {}
