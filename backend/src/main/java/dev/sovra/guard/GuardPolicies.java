package dev.sovra.guard;

import java.util.List;
import java.util.Map;

/**
 * Frozen G1 policy documents (SOV-014). Production policy documents
 * arrive with versioned RP policy management; G1 carries synthetic
 * documents only, always labelled synthetic, never a production authority.
 *
 * <p>The original {@code age-check} v1 is FROZEN with budget
 * {@code ["adultOver18"]} only and is never silently expanded. Mapped
 * unfamiliar-schema flows use the distinct {@code age-check-mapped} v1,
 * whose budget covers every registry-approved wire spelling of the same
 * {@code age_over_18} semantic. The UI selects which policy to use.
 */
public final class GuardPolicies {

  public static final String POLICY_ID = "sovra-synthetic-policy/age-check";
  public static final String POLICY_VERSION = "1";
  public static final String SECTION_ID = "age_eligibility";

  public static final String MAPPED_POLICY_ID = "sovra-synthetic-policy/age-check-mapped";
  public static final String MAPPED_POLICY_VERSION = "1";
  public static final String MAPPED_SECTION_ID = "mapped_age_eligibility";

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
            List.of("adultOver18")),
        MAPPED_POLICY_ID,
        new PolicyDocument(
            MAPPED_POLICY_ID,
            MAPPED_POLICY_VERSION,
            Map.of(
                MAPPED_SECTION_ID,
                "For this synthetic service, request evidence that the holder"
                    + " is at least 18 years old under any registry-approved"
                    + " wire spelling of that semantic (adultOver18, isAdult,"
                    + " qualifiesAsAdult); no birth date or source document"
                    + " is disclosed. Governed by sovra-synthetic-schemas/1."),
            List.of("adultOver18", "isAdult", "qualifiesAsAdult")));
  }

  /** Section id for one approved RP policy binding, or null if unapproved. */
  public static String sectionFor(String policyId, String policyVersion) {
    if (POLICY_ID.equals(policyId) && POLICY_VERSION.equals(policyVersion)) {
      return SECTION_ID;
    }
    if (MAPPED_POLICY_ID.equals(policyId) && MAPPED_POLICY_VERSION.equals(policyVersion)) {
      return MAPPED_SECTION_ID;
    }
    return null;
  }
}
