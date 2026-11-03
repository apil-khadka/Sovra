package dev.sovra.guard;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * Shared versioned approved synthetic schema/semantics registry (governed
 * unfamiliar-schema discovery). One frozen code table consumed by planning
 * tools, the deterministic guard, and issuance/verifier validation — not a
 * fixture-specific if/else adapter.
 *
 * <p>Each entry binds ONE wire {@code (vct, claim)} pair to ONE semantic
 * outcome. The guard requires the entry to exist FOR THAT TYPE (union
 * membership never authorizes) and requires the entry's semantic to equal
 * the plan's {@code requestedOutcome}. Unknown pairs attest nothing;
 * the employment-tenure entry is explicitly incompatible with
 * {@code age_over_18} so {@code yearsInEmployment>=18} can never satisfy
 * an age proof, whatever value it carries.
 *
 * <p>No model-authored text creates authority here: the table is static
 * frozen code, trust snapshots pin which issuers may attest which types,
 * and the guard remains the only approver. Tool outputs cite this
 * registry version so runs reproduce.
 *
 * <p>PROFILE BOUNDARY: new schemas ({@code fjord-adult}, {@code harbor-adult})
 * are synthetic-profile-only. The SD-JWT VC profile, VCI/VP transports, and
 * DCQL stay legacy {@code adult-status/1} + {@code adultOver18}-only.
 */
public final class ApprovedSchemas {

  /** Registry version, cited in every tool output and evaluation report. */
  public static final String REGISTRY_VERSION = "sovra-synthetic-schemas/1";

  /** Semantic outcome for age proofs; equals the G1 planning outcome. */
  public static final String SEMANTIC_AGE_OVER_18 = "age_over_18";

  /** Second fictional compatible schema (Fjord jurisdiction). */
  public static final String FJORD_VCT = "https://sovra.example/vct/fjord-adult/1";

  /** Third fictional compatible schema (Harbor jurisdiction). */
  public static final String HARBOR_VCT = "https://sovra.example/vct/harbor-adult/1";

  /** Explicitly incompatible schema: tenure is not proof of age. */
  public static final String EMPLOYMENT_VCT =
      "https://sovra.example/vct/employment-tenure/1";

  /** Legacy short type name from the frozen guard corpus (alias, not new authority). */
  static final String LEGACY_ADULT_TYPE = "AdultStatusCredential";

  /** One approved wire mapping with its citable source anchor. */
  public record SchemaEntry(
      String vct,
      String claim,
      String semantic,
      String claimType,
      String meaning,
      String predicate,
      String schemaId,
      String sectionId,
      boolean compatible) {}

  private static final List<SchemaEntry> ENTRIES = List.of(
      new SchemaEntry(
          dev.sovra.issuance.SyntheticJwtEncoder.ADULT_VCT,
          "adultOver18",
          SEMANTIC_AGE_OVER_18,
          "boolean",
          "Holder is at least 18 years old at issuance.",
          "claim == true",
          "sovra-schema/adult-status-v1",
          "adult_status",
          true),
      new SchemaEntry(
          FJORD_VCT,
          "isAdult",
          SEMANTIC_AGE_OVER_18,
          "boolean",
          "Holder has reached 18 years of age at issuance (fictional Fjord"
              + " jurisdiction; equal semantics, adequate assurance).",
          "claim == true",
          "sovra-schema/fjord-adult-v1",
          "adult_eligibility",
          true),
      new SchemaEntry(
          HARBOR_VCT,
          "qualifiesAsAdult",
          SEMANTIC_AGE_OVER_18,
          "boolean",
          "Holder qualifies as an adult at issuance (fictional Harbor"
              + " jurisdiction; equal semantics).",
          "claim == true",
          "sovra-schema/harbor-adult-v1",
          "adult_qualification",
          true),
      new SchemaEntry(
          EMPLOYMENT_VCT,
          "yearsInEmployment",
          "employment_tenure_years",
          "integer",
          "Years the holder has been employed. Tenure is not proof of age"
              + " and MUST NOT satisfy age_over_18 at any value.",
          "value >= 0; never satisfies age_over_18",
          "sovra-schema/employment-tenure-v1",
          "tenure",
          false));

  private ApprovedSchemas() {}

  public static String version() {
    return REGISTRY_VERSION;
  }

  public static List<SchemaEntry> entries() {
    return ENTRIES;
  }

  /**
   * Compatible wire claims attestable for one type. Unknown and explicitly
   * incompatible types attest nothing, so unfamiliar schemas fail closed
   * without code changes.
   */
  public static List<String> forType(String vct) {
    if (vct == null) {
      return List.of();
    }
    String normalized = LEGACY_ADULT_TYPE.equals(vct)
        ? dev.sovra.issuance.SyntheticJwtEncoder.ADULT_VCT
        : vct;
    return ENTRIES.stream()
        .filter(e -> e.compatible() && normalized.equals(e.vct()))
        .map(SchemaEntry::claim)
        .toList();
  }

  /** Full metadata for one type, including explicitly incompatible entries. */
  public static Optional<SchemaEntry> metadataFor(String vct) {
    if (vct == null) {
      return Optional.empty();
    }
    String normalized = LEGACY_ADULT_TYPE.equals(vct)
        ? dev.sovra.issuance.SyntheticJwtEncoder.ADULT_VCT
        : vct;
    return ENTRIES.stream().filter(e -> normalized.equals(e.vct())).findFirst();
  }

  /** Registry semantic for one exact wire pair, if approved in any form. */
  public static Optional<String> semanticFor(String vct, String claim) {
    if (vct == null || claim == null) {
      return Optional.empty();
    }
    String normalized = LEGACY_ADULT_TYPE.equals(vct)
        ? dev.sovra.issuance.SyntheticJwtEncoder.ADULT_VCT
        : vct;
    return ENTRIES.stream()
        .filter(e -> normalized.equals(e.vct()) && claim.equals(e.claim()))
        .map(SchemaEntry::semantic)
        .findFirst();
  }

  /**
   * Type-specific authorization: the wire pair must be a compatible entry
   * FOR THAT TYPE. A claim approved for one type never authorizes another
   * type, even when one issuer attests both.
   */
  public static boolean allows(String vct, String claim) {
    if (vct == null || claim == null) {
      return false;
    }
    String normalized = LEGACY_ADULT_TYPE.equals(vct)
        ? dev.sovra.issuance.SyntheticJwtEncoder.ADULT_VCT
        : vct;
    return ENTRIES.stream()
        .anyMatch(e -> e.compatible()
            && normalized.equals(e.vct())
            && claim.equals(e.claim()));
  }

  /** Compatible wire names for one semantic outcome (planning intents). */
  public static List<String> approvedClaimsForOutcome(String outcome) {
    if (outcome == null) {
      return List.of();
    }
    return ENTRIES.stream()
        .filter(e -> e.compatible() && outcome.equals(e.semantic()))
        .map(SchemaEntry::claim)
        .toList();
  }

  /**
   * Citable schema documents for guard evidence. Schema docs are evidence
   * only — never selectable as the RP intent policy.
   */
  public static Map<String, PolicyDocument> documents() {
    Map<String, PolicyDocument> docs = new TreeMap<>();
    for (SchemaEntry entry : ENTRIES) {
      docs.put(
          entry.schemaId(),
          new PolicyDocument(
              entry.schemaId(),
              "1",
              Map.of(entry.sectionId(),
                  entry.meaning() + " Predicate: " + entry.predicate()
                      + " Semantic: " + entry.semantic() + "."
                      + " Registry: " + REGISTRY_VERSION + "."),
              List.of(entry.claim())));
    }
    return Map.copyOf(docs);
  }

  /**
   * Canonical claims form for issuance/consent proof messages: sorted
   * {@code key=value} pairs joined by commas. Single-claim G1 flows render
   * as {@code adultOver18=true} — byte-identical to the legacy constant.
   */
  public static String canonicalClaims(Map<String, ?> claims) {
    if (claims == null || claims.isEmpty()) {
      throw new IllegalArgumentException("claims are missing");
    }
    StringBuilder canonical = new StringBuilder();
    boolean first = true;
    for (Map.Entry<String, ?> entry : new TreeMap<>(claims).entrySet()) {
      if (entry.getKey() == null || entry.getValue() == null) {
        throw new IllegalArgumentException("claim name or value is missing");
      }
      if (!first) {
        canonical.append(",");
      }
      first = false;
      canonical.append(entry.getKey()).append("=").append(String.valueOf(entry.getValue()));
    }
    return canonical.toString();
  }
}
