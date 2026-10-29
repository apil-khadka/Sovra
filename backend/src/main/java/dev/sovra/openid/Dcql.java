package dev.sovra.openid;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Minimal DCQL query support for the G1 single-credential profile
 * (SOV-036). Builds the verifier's credential query for one
 * {@code dc+sd-jwt} credential and matches a presented credential
 * against it: format, {@code vct} allowlist, and disclosed claim
 * paths/values. Multi-credential queries, credential sets, and
 * trusted-authority clauses are outside the frozen profile and are
 * rejected rather than partially evaluated.
 */
public final class Dcql {

  static final String CREDENTIAL_ID = "sovra-adult-status";
  static final String CLAIM_ID = "adult-flag";

  private Dcql() {}

  /** Verifier query for the G1 adult-status credential. */
  public static Map<String, Object> queryFor(String vct) {
    Map<String, Object> claim = new LinkedHashMap<>();
    claim.put("id", CLAIM_ID);
    claim.put("path", List.of("claims", "adultOver18"));
    claim.put("values", List.of(Boolean.TRUE));
    Map<String, Object> credential = new LinkedHashMap<>();
    credential.put("id", CREDENTIAL_ID);
    credential.put("format", "dc+sd-jwt");
    credential.put("meta", Map.of("vct_values", List.of(vct)));
    credential.put("claims", List.of(claim));
    return Map.of("credentials", List.of(credential));
  }

  /**
   * Matches one presented credential against the query the verifier
   * issued. Returns empty on fulfillment, or the mismatch reason.
   *
   * @param query the {@code dcql_query} object from the request
   * @param format presented credential format (must be {@code dc+sd-jwt})
   * @param vct presented credential {@code vct}
   * @param disclosedClaims disclosed claim object (the {@code claims} node)
   */
  public static Optional<String> match(
      JsonNode query, String format, String vct, JsonNode disclosedClaims) {
    if (query == null || !query.isObject()) {
      return Optional.of("DCQL_QUERY_MISSING");
    }
    JsonNode credentials = query.get("credentials");
    if (credentials == null || !credentials.isArray() || credentials.size() != 1) {
      return Optional.of("DCQL_SHAPE_UNSUPPORTED");
    }
    JsonNode credential = credentials.get(0);
    if (!CREDENTIAL_ID.equals(text(credential, "id"))
        || !"dc+sd-jwt".equals(text(credential, "format"))) {
      return Optional.of("DCQL_SHAPE_UNSUPPORTED");
    }
    if (!"dc+sd-jwt".equals(format)) {
      return Optional.of("FORMAT_MISMATCH");
    }
    JsonNode meta = credential.get("meta");
    JsonNode vcts = meta == null ? null : meta.get("vct_values");
    if (vcts == null || !vcts.isArray() || vcts.size() == 0) {
      return Optional.of("DCQL_SHAPE_UNSUPPORTED");
    }
    boolean allowed = false;
    for (JsonNode candidate : vcts) {
      if (candidate.isString() && candidate.asString().equals(vct)) {
        allowed = true;
        break;
      }
    }
    if (!allowed) {
      return Optional.of("VCT_MISMATCH");
    }
    JsonNode claims = credential.get("claims");
    if (claims == null || !claims.isArray() || claims.size() == 0) {
      return Optional.of("DCQL_SHAPE_UNSUPPORTED");
    }
    List<String> failures = new ArrayList<>();
    for (JsonNode claim : claims) {
      String id = text(claim, "id");
      JsonNode path = claim.get("path");
      JsonNode values = claim.get("values");
      if (id == null || path == null || !path.isArray() || path.size() == 0) {
        return Optional.of("DCQL_SHAPE_UNSUPPORTED");
      }
      List<String> segments = new ArrayList<>();
      for (JsonNode segment : path) {
        if (!segment.isString()) {
          return Optional.of("DCQL_SHAPE_UNSUPPORTED");
        }
        segments.add(segment.asString());
      }
      JsonNode actual = disclosedClaims;
      // Paths are relative to the disclosed claim object when they
      // start with "claims" (the G1 credential nests values there).
      int start = !segments.isEmpty() && "claims".equals(segments.get(0)) ? 1 : 0;
      for (int i = start; i < segments.size() && actual != null; i++) {
        actual = actual.get(segments.get(i));
      }
      if (actual == null || actual.isMissingNode() || actual.isNull()) {
        failures.add(id);
        continue;
      }
      if (values != null && values.isArray() && values.size() > 0) {
        boolean any = false;
        for (JsonNode allowedValue : values) {
          if (allowedValue.equals(actual)) {
            any = true;
            break;
          }
        }
        if (!any) {
          failures.add(id);
        }
      }
    }
    if (!failures.isEmpty()) {
      return Optional.of("CLAIMS_MISMATCH");
    }
    return Optional.empty();
  }

  /** Presentation submission mapping the response to the G1 query. */
  public static Map<String, Object> submission() {
    return Map.of(
        "id", "sovra-presentation",
        "definition_id", CREDENTIAL_ID,
        "descriptor_map",
            List.of(
                Map.of(
                    "id", CLAIM_ID,
                    "format", "dc+sd-jwt",
                    "path", "$",
                    "path_nested",
                        Map.of(
                            "format", "dc+sd-jwt",
                            "path", "$.vp_token"))));
  }

  private static String text(JsonNode node, String field) {
    JsonNode child = node == null ? null : node.get(field);
    return child != null && child.isString() ? child.asString() : null;
  }

  /** Parses untrusted DCQL JSON with a size bound. */
  public static JsonNode parseQuery(String raw, ObjectMapper mapper, int maxChars) {
    if (raw == null || raw.length() > maxChars) {
      throw new InvalidOpenIdRequestException("dcql query is too large");
    }
    try {
      return mapper.readTree(raw);
    } catch (Exception e) {
      throw new InvalidOpenIdRequestException("dcql query is malformed");
    }
  }
}
