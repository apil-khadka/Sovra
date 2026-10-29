package dev.sovra.planning;

import dev.sovra.audit.AuditService;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ResourceRef;
import dev.sovra.guard.GuardClaims;
import dev.sovra.guard.GuardPolicies;
import dev.sovra.guard.PolicyDocument;
import dev.sovra.trust.TrustSnapshotProvider;
import dev.sovra.issuance.TrustUnavailableException;
import dev.sovra.trust.IssuerKeys;
import dev.sovra.trust.TrustService;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import org.springframework.ai.chat.model.ToolContext;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.DefaultToolDefinition;
import org.springframework.ai.tool.definition.ToolDefinition;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Bounded read-only planning tools (SOV-013, FR-05, SR-08). Exactly the
 * five discovery tools from the agent contract exist; every callback
 * reauthorizes the live caller, validates arguments against allowlists,
 * charges the per-request budget, and reads only the active trust
 * snapshot plus the frozen G1 policy documents. The tools take no URLs,
 * make no network calls, perform no writes, and return minimized
 * metadata — never keys, tokens, credentials, or proofs (DR-03).
 */
@Service
public class PlanningTools {

  static final int MAX_ARG_CHARS = 256;
  static final int MAX_CANDIDATES = 8;

  static final String LIST_ISSUERS = "listTrustedIssuers";
  static final String GET_SCHEMA = "getCredentialSchema";
  static final String GET_POLICY = "getPolicyDocument";
  static final String GET_CAPABILITIES = "getIssuerCapabilities";
  static final String COMPARE = "compareEvidence";

  /** Argument members that would smuggle authority; never honored (IF-02). */
  private static final Set<String> FORBIDDEN_ARGS =
      Set.of("tenantId", "tenant", "accountId", "role", "roles", "token", "apiKey");

  private final AuthorizationService authz;
  private final AuditService audit;
  private final TrustSnapshotProvider snapshots;
  private final Clock clock;
  private final ObjectMapper mapper;
  private final List<ToolCallback> callbacks;
  private final Map<String, ToolCallback> byName;

  public PlanningTools(
      AuthorizationService authz,
      AuditService audit,
      TrustSnapshotProvider snapshots,
      Clock clock,
      ObjectMapper mapper) {
    this.authz = authz;
    this.audit = audit;
    this.snapshots = snapshots;
    this.clock = clock;
    this.mapper = mapper;
    this.callbacks =
        List.of(
            tool(
                LIST_ISSUERS,
                "List currently usable trusted issuers for an outcome and jurisdiction hint."
                    + " Returns issuer ids, scopes, credential types, and standing only.",
                """
                {"type":"object","properties":{"outcome":{"type":"string","maxLength":256},\
                "jurisdiction":{"type":"string","maxLength":256}},"additionalProperties":false}\
                """,
                this::listTrustedIssuers),
            tool(
                GET_SCHEMA,
                "Fetch the versioned claim schema for one exact trusted issuer id and credential"
                    + " type. Unknown ids fail closed with unknown_issuer.",
                """
                {"type":"object","properties":{"issuerId":{"type":"string","maxLength":256},\
                "credentialType":{"type":"string","maxLength":256}},"required":["issuerId",\
                "credentialType"],"additionalProperties":false}\
                """,
                this::getCredentialSchema),
            tool(
                GET_POLICY,
                "Fetch one exact versioned policy document with its source sections and disclosure"
                    + " budget. Only approved policy bindings resolve.",
                """
                {"type":"object","properties":{"policyId":{"type":"string","maxLength":256},\
                "version":{"type":"string","maxLength":256}},"required":["policyId","version"],\
                "additionalProperties":false}\
                """,
                this::getPolicyDocument),
            tool(
                GET_CAPABILITIES,
                "Fetch one exact trusted issuer's supported credential types, scopes, and standing."
                    + " Unknown ids fail closed with unknown_issuer.",
                """
                {"type":"object","properties":{"issuerId":{"type":"string","maxLength":256}},\
                "required":["issuerId"],"additionalProperties":false}\
                """,
                this::getIssuerCapabilities),
            tool(
                COMPARE,
                "Deterministic compatibility hints for candidate credentials against one outcome."
                    + " Pure function over pinned registry metadata; never an authorization.",
                """
                {"type":"object","properties":{"requestedOutcome":{"type":"string",\
                "maxLength":256},"candidateCredentialIds":{"type":"array","maxItems":8,\
                "items":{"type":"string","maxLength":256}}},"required":["requestedOutcome",\
                "candidateCredentialIds"],"additionalProperties":false}\
                """,
                this::compareEvidence));
    Map<String, ToolCallback> index = new TreeMap<>();
    for (ToolCallback callback : callbacks) {
      index.put(callback.getToolDefinition().name(), callback);
    }
    this.byName = Map.copyOf(index);
  }

  private ToolCallback tool(
      String name,
      String description,
      String schema,
      java.util.function.BiFunction<String, ToolContext, String> fn) {
    // Hand-rolled callback, not a reflective function adapter: the raw
    // argument string reaches the strict validator below with no
    // framework conversion, coercion, or leniency in between.
    ToolDefinition definition =
        DefaultToolDefinition.builder()
            .name(name)
            .description(description)
            .inputSchema(schema)
            .build();
    return new ToolCallback() {
      @Override
      public ToolDefinition getToolDefinition() {
        return definition;
      }

      @Override
      public String call(String toolInput) {
        return fn.apply(toolInput, new ToolContext(Map.of()));
      }

      @Override
      public String call(String toolInput, ToolContext toolContext) {
        return fn.apply(toolInput, toolContext);
      }
    };
  }

  /** The exact tool set offered to the model; nothing else exists. */
  public List<ToolCallback> callbacks() {
    return callbacks;
  }

  /**
   * Resolves one tool by exact name (SEC-16). Hidden, misspelled, or
   * model-invented tool names fail closed here, before any work.
   */
  public ToolCallback dispatch(String name) {
    ToolCallback callback = name == null ? null : byName.get(name);
    if (callback == null) {
      throw new InvalidPlanningException("unknown planning tool");
    }
    return callback;
  }

  /**
   * Reauthorizes the live caller and charges the budget ahead of every
   * tool body (SR-08). Denials audit and abort with the caller's 403;
   * exhaustion ends the run as unavailable. Calls outside an installed
   * invocation fail closed without touching the registry.
   */
  private PlanningInvocation authorizeToolCall() {
    PlanningInvocation invocation =
        PlanningInvocation.current()
            .orElseThrow(
                () -> new IllegalStateException("planning tool outside an authorized invocation"));
    var caller = invocation.caller();
    Decision decision =
        authz.authorize(
            Optional.of(caller),
            Action.PROPOSE_PLAN,
            ResourceRef.tenantScoped("planning", "tools", caller.tenantId()));
    if (!decision.permitted()) {
      audit.recordDenial(
          caller, Action.PROPOSE_PLAN,
          ResourceRef.tenantScoped("planning", "tools", caller.tenantId()),
          decision.reasonCode(), decision.policyVersion());
      throw new ForbiddenException(decision.reasonCode());
    }
    invocation.charge();
    return invocation;
  }

  /** Strict argument object: allowlisted members, bounded strings, no authority. */
  private Map<String, String> args(String input, Set<String> allowed) {
    return args(input, allowed, Set.of());
  }

  /**
   * Strict argument object with narrow numeric tolerance: members in
   * {@code numericExact} additionally accept integral JSON numbers
   * (OD-02: models naturally emit {@code "version": 1}), normalized
   * by exact canonical form under the same length bound. Nothing
   * else changes: unknown members, non-integral numbers, booleans,
   * arrays, objects, and authority-smuggling members still fail.
   */
  private Map<String, String> args(
      String input, Set<String> allowed, Set<String> numericExact) {
    JsonNode root;
    try {
      root = mapper.readTree(input);
    } catch (RuntimeException e) {
      throw new InvalidPlanningException("tool arguments are not JSON");
    }
    if (root == null || !root.isObject()) {
      throw new InvalidPlanningException("tool arguments must be an object");
    }
    Map<String, String> parsed = new LinkedHashMap<>();
    for (Map.Entry<String, JsonNode> field : root.properties()) {
      String name = field.getKey();
      if (FORBIDDEN_ARGS.contains(name)) {
        throw new InvalidPlanningException("tool arguments must not carry authority");
      }
      if (!allowed.contains(name)) {
        throw new InvalidPlanningException("unsupported tool argument: " + name);
      }
      JsonNode value = field.getValue();
      String text;
      if (value.isString()) {
        text = value.asText();
      } else if (numericExact.contains(name) && value.isIntegralNumber()) {
        text = value.asText();
      } else {
        throw new InvalidPlanningException("unsupported tool argument: " + name);
      }
      if (text.length() > MAX_ARG_CHARS) {
        throw new InvalidPlanningException("tool argument exceeds its bound: " + name);
      }
      parsed.put(name, text);
    }
    return parsed;
  }

  private String errorJson(String code) {
    return "{\"error\":\"" + code + "\"}";
  }

  private String toJson(Object value) {
    try {
      return mapper.writeValueAsString(value);
    } catch (RuntimeException e) {
      throw new IllegalStateException("tool result is not serializable", e);
    }
  }

  private TrustService.SnapshotView activeSnapshot() {
    return snapshots.current().orElseThrow(TrustUnavailableException::new);
  }

  private String listTrustedIssuers(String input, ToolContext context) {
    authorizeToolCall();
    Map<String, String> arguments = args(input, Set.of("outcome", "jurisdiction"));
    TrustService.SnapshotView snapshot = activeSnapshot();
    InstantView now = new InstantView(clock.instant());
    List<Map<String, Object>> issuers = new ArrayList<>();
    for (TrustService.IssuerView issuer : snapshot.issuers()) {
      // First row wins per issuer, matching the guard and verifier.
      if (!IssuerKeys.usable(issuer, now.value())
          || issuers.stream().anyMatch(row -> issuer.issuerId().equals(row.get("issuerId")))) {
        continue;
      }
      // Hints filter; they never widen beyond usable snapshot issuers.
      String jurisdiction = arguments.get("jurisdiction");
      if (jurisdiction != null && !jurisdiction.isBlank()
          && !issuer.scope().contains(jurisdiction)) {
        continue;
      }
      Map<String, Object> row = new LinkedHashMap<>();
      row.put("issuerId", issuer.issuerId());
      row.put("scope", issuer.scope());
      row.put("credentialTypes", issuer.credentialTypes());
      row.put("status", issuer.status());
      row.put("validThrough", issuer.validThrough().toString());
      issuers.add(row);
    }
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("snapshotVersion", snapshot.version());
    result.put("issuers", issuers);
    return toJson(result);
  }

  private String getCredentialSchema(
      String input, ToolContext context) {
    authorizeToolCall();
    Map<String, String> arguments = args(input, Set.of("issuerId", "credentialType"));
    String issuerId = arguments.get("issuerId");
    String credentialType = arguments.get("credentialType");
    if (issuerId == null || credentialType == null) {
      throw new InvalidPlanningException("issuerId and credentialType are required");
    }
    TrustService.SnapshotView snapshot = activeSnapshot();
    TrustService.IssuerView issuer =
        snapshot.issuers().stream()
            .filter(i -> issuerId.equals(i.issuerId()))
            .findFirst()
            .orElse(null);
    if (issuer == null) {
      return errorJson("unknown_issuer");
    }
    // Attestable claims come from the shared G1 allowlist; unfamiliar
    // schemas attest nothing and fail closed without code changes.
    List<String> claims =
        issuer.credentialTypes().contains(credentialType)
            ? GuardClaims.forType(credentialType)
            : List.of();
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("issuerId", issuer.issuerId());
    result.put("credentialType", credentialType);
    result.put("claims", claims);
    result.put("snapshotVersion", snapshot.version());
    return toJson(result);
  }

  private String getPolicyDocument(
      String input, ToolContext context) {
    authorizeToolCall();
    // Policy versions read numeric to models; accept 1 as "1" exactly.
    Map<String, String> arguments = args(input, Set.of("policyId", "version"), Set.of("version"));
    String policyId = arguments.get("policyId");
    String version = arguments.get("version");
    if (policyId == null || version == null) {
      throw new InvalidPlanningException("policyId and version are required");
    }
    PolicyDocument document = GuardPolicies.documents().get(policyId);
    if (document == null || !document.version().equals(version)) {
      return errorJson("unknown_policy");
    }
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("policyId", document.documentId());
    result.put("version", document.version());
    result.put("sections", document.sections());
    result.put("disclosureBudget", document.approvedClaims());
    return toJson(result);
  }

  private String getIssuerCapabilities(
      String input, ToolContext context) {
    authorizeToolCall();
    Map<String, String> arguments = args(input, Set.of("issuerId"));
    String issuerId = arguments.get("issuerId");
    if (issuerId == null) {
      throw new InvalidPlanningException("issuerId is required");
    }
    TrustService.SnapshotView snapshot = activeSnapshot();
    TrustService.IssuerView issuer =
        snapshot.issuers().stream()
            .filter(i -> issuerId.equals(i.issuerId()))
            .findFirst()
            .orElse(null);
    if (issuer == null) {
      return errorJson("unknown_issuer");
    }
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("issuerId", issuer.issuerId());
    result.put("credentialTypes", issuer.credentialTypes());
    result.put("scope", issuer.scope());
    result.put("status", issuer.status());
    result.put("usable", IssuerKeys.usable(issuer, clock.instant()));
    result.put("validThrough", issuer.validThrough().toString());
    result.put("snapshotVersion", snapshot.version());
    return toJson(result);
  }

  private String compareEvidence(
      String input, ToolContext context) {
    authorizeToolCall();
    JsonNode root;
    try {
      root = mapper.readTree(input);
    } catch (RuntimeException e) {
      throw new InvalidPlanningException("tool arguments are not JSON");
    }
    if (root == null || !root.isObject()) {
      throw new InvalidPlanningException("tool arguments must be an object");
    }
    for (String forbidden : FORBIDDEN_ARGS) {
      if (root.has(forbidden)) {
        throw new InvalidPlanningException("tool arguments must not carry authority");
      }
    }
    JsonNode outcome = root.get("requestedOutcome");
    JsonNode candidates = root.get("candidateCredentialIds");
    if (outcome == null
        || !outcome.isString()
        || outcome.asText().length() > MAX_ARG_CHARS
        || candidates == null
        || !candidates.isArray()
        || candidates.size() > MAX_CANDIDATES) {
      throw new InvalidPlanningException("compareEvidence arguments are malformed");
    }
    for (Map.Entry<String, JsonNode> field : root.properties()) {
      String name = field.getKey();
      if (!Set.of("requestedOutcome", "candidateCredentialIds").contains(name)) {
        throw new InvalidPlanningException("unsupported tool argument: " + name);
      }
    }
    TrustService.SnapshotView snapshot = activeSnapshot();
    InstantView now = new InstantView(clock.instant());
    List<Map<String, String>> hints = new ArrayList<>();
    for (JsonNode candidate : candidates) {
      if (!candidate.isString() || candidate.asText().length() > MAX_ARG_CHARS) {
        throw new InvalidPlanningException("candidate id exceeds its bound");
      }
      hints.add(hint(snapshot, now.value(), outcome.asText(), candidate.asText()));
    }
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("snapshotVersion", snapshot.version());
    result.put("hints", hints);
    return toJson(result);
  }

  /**
   * One deterministic hint. Candidate ids are {@code issuerId|credentialType};
   * anything else is unknown. Hints describe registry facts only; the
   * guard remains the only authority that accepts a plan.
   */
  private Map<String, String> hint(
      TrustService.SnapshotView snapshot, java.time.Instant now, String outcome, String id) {
    int sep = id.indexOf('|');
    String issuerId = sep < 0 ? "" : id.substring(0, sep);
    String credentialType = sep < 0 ? "" : id.substring(sep + 1);
    TrustService.IssuerView issuer =
        snapshot.issuers().stream()
            .filter(i -> issuerId.equals(i.issuerId()))
            .findFirst()
            .orElse(null);
    String verdict;
    String detail;
    if (issuer == null || issuerId.isEmpty() || credentialType.isEmpty()) {
      verdict = "unknown";
      detail = "candidate is not pinned registry metadata";
    } else if (!PlanningIntents.OUTCOME.equals(outcome)) {
      verdict = "unsupported";
      detail = "outcome is outside the G1 allowlist";
    } else if (!IssuerKeys.usable(issuer, now)) {
      verdict = "unusable";
      detail = "issuer is not currently usable";
    } else if (!issuer.credentialTypes().contains(credentialType)
        || GuardClaims.forType(credentialType).isEmpty()) {
      verdict = "incompatible";
      detail = "credential type attests no supported claim";
    } else {
      verdict = "compatible";
      detail = "credential type attests a supported claim";
    }
    Map<String, String> row = new LinkedHashMap<>();
    row.put("candidateId", id);
    row.put("verdict", verdict);
    row.put("detail", detail);
    return row;
  }

  /** Tiny carrier so lambdas stay readable. */
  private record InstantView(java.time.Instant value) {}
}
