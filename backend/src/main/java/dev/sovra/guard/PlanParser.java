package dev.sovra.guard;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import tools.jackson.databind.JsonNode;

/**
 * Strict guard-schema parser (SOV-014). Converts JSON into guard
 * records or throws {@link MalformedPlanException}: wrong types,
 * missing required fields, unknown recommendation values, and
 * unparseable instants are incompatible schemas, never best-effort
 * coercions. Unknown extra fields are ignored for forward
 * compatibility; they authorize nothing.
 */
public final class PlanParser {

  private PlanParser() {}

  public static CandidatePlan parsePlan(JsonNode node) {
    if (node == null || !node.isObject()) {
      throw new MalformedPlanException();
    }
    return new CandidatePlan(
        text(node, "plan_id"),
        text(node, "requested_outcome"),
        text(node, "candidate_issuer_id"),
        text(node, "credential_type"),
        strings(node, "claim_paths"),
        citations(node),
        text(node, "policy_id"),
        text(node, "policy_version"),
        recommendation(node));
  }

  public static GuardContext parseContext(JsonNode node) {
    if (node == null || !node.isObject()) {
      throw new MalformedPlanException();
    }
    JsonNode issuers = node.get("trusted_issuers");
    JsonNode policies = node.get("policies");
    if (issuers == null || !issuers.isObject() || policies == null || !policies.isObject()) {
      throw new MalformedPlanException();
    }
    Map<String, TrustedIssuer> trusted = new LinkedHashMap<>();
    for (Map.Entry<String, JsonNode> entry : issuers.properties()) {
      TrustedIssuer issuer = parseIssuer(entry.getValue());
      trusted.put(entry.getKey(), issuer);
    }
    Map<String, PolicyDocument> docs = new LinkedHashMap<>();
    for (Map.Entry<String, JsonNode> entry : policies.properties()) {
      PolicyDocument doc = parsePolicy(entry.getValue());
      docs.put(entry.getKey(), doc);
    }
    return new GuardContext(Map.copyOf(trusted), Map.copyOf(docs));
  }

  /** Trusted RP policy selection; blank or mistyped bindings are malformed. */
  public static SelectedPolicy parseSelected(String policyId, String policyVersion) {
    if (policyId == null || policyId.isBlank() || policyVersion == null
        || policyVersion.isBlank()) {
      throw new MalformedPlanException();
    }
    return new SelectedPolicy(policyId, policyVersion);
  }

  private static TrustedIssuer parseIssuer(JsonNode node) {
    if (node == null || !node.isObject()) {
      throw new MalformedPlanException();
    }
    return new TrustedIssuer(
        text(node, "issuer_id"),
        strings(node, "allowed_credential_types"),
        strings(node, "allowed_claims"),
        strings(node, "key_ids"),
        standing(node),
        instant(node, "valid_from"),
        instant(node, "valid_through"));
  }

  /**
   * Standing from context JSON. Unknown text is malformed input,
   * not a standing verdict; a missing field stays null and refuses
   * closed in the standing check.
   */
  private static dev.sovra.trust.IssuerStatus standing(JsonNode node) {
    String status = text(node, "status");
    if (status == null) {
      return null;
    }
    try {
      return dev.sovra.trust.IssuerStatus.from(status);
    } catch (IllegalArgumentException e) {
      throw new MalformedPlanException();
    }
  }

  private static PolicyDocument parsePolicy(JsonNode node) {
    if (node == null || !node.isObject()) {
      throw new MalformedPlanException();
    }
    JsonNode sections = node.get("sections");
    if (sections == null || !sections.isObject()) {
      throw new MalformedPlanException();
    }
    Map<String, String> map = new LinkedHashMap<>();
    for (Map.Entry<String, JsonNode> entry : sections.properties()) {
      if (!entry.getValue().isString()) {
        throw new MalformedPlanException();
      }
      map.put(entry.getKey(), entry.getValue().asString());
    }
    return new PolicyDocument(
        text(node, "document_id"), text(node, "version"), Map.copyOf(map),
        strings(node, "approved_claims"));
  }

  private static List<EvidenceCitation> citations(JsonNode node) {
    JsonNode evidence = node.get("evidence");
    if (evidence == null || !evidence.isArray()) {
      throw new MalformedPlanException();
    }
    List<EvidenceCitation> citations = new ArrayList<>();
    for (int i = 0; i < evidence.size(); i++) {
      JsonNode citation = evidence.get(i);
      if (citation == null || !citation.isObject()) {
        throw new MalformedPlanException();
      }
      citations.add(new EvidenceCitation(text(citation, "document_id"), text(citation, "section_id")));
    }
    return List.copyOf(citations);
  }

  private static Recommendation recommendation(JsonNode node) {
    JsonNode child = node.get("recommendation");
    if (child == null || !child.isString()) {
      throw new MalformedPlanException();
    }
    try {
      return Recommendation.valueOf(child.asString());
    } catch (IllegalArgumentException e) {
      throw new MalformedPlanException();
    }
  }

  private static String text(JsonNode node, String field) {
    JsonNode child = node.get(field);
    if (child == null || !child.isString()) {
      throw new MalformedPlanException();
    }
    return child.asString();
  }

  private static List<String> strings(JsonNode node, String field) {
    JsonNode child = node.get(field);
    if (child == null || !child.isArray()) {
      throw new MalformedPlanException();
    }
    List<String> values = new ArrayList<>();
    for (int i = 0; i < child.size(); i++) {
      JsonNode item = child.get(i);
      if (item == null || !item.isString()) {
        throw new MalformedPlanException();
      }
      values.add(item.asString());
    }
    return List.copyOf(values);
  }

  private static Instant instant(JsonNode node, String field) {
    try {
      return Instant.parse(text(node, field));
    } catch (java.time.format.DateTimeParseException e) {
      throw new MalformedPlanException();
    }
  }
}
