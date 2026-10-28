package dev.sovra.guard;

import java.util.List;
import java.util.Map;

/**
 * Frozen G1 policy documents (SOV-014). Production policy documents
 * arrive with versioned RP policy management; G1 carries exactly one
 * synthetic document whose budget covers the adult-status claim only.
 * Always labelled synthetic, never a production authority.
 */
public final class GuardPolicies {

  public static final String POLICY_ID = "sovra-synthetic-policy/age-check";
  public static final String POLICY_VERSION = "1";
  public static final String SECTION_ID = "age_eligibility";

  private GuardPolicies() {}

  public static Map<String, PolicyDocument> documents() {
    return Map.of(
        POLICY_ID,
        new PolicyDocument(
            POLICY_ID,
            POLICY_VERSION,
            Map.of(
                SECTION_ID,
                "For this synthetic service, request evidence that the holder"
                    + " is at least 18 years old; no birth date or source"
                    + " document is disclosed."),
            List.of("adultOver18")));
  }
}
