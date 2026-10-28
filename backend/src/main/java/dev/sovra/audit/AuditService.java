package dev.sovra.audit;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ResourceRef;
import dev.sovra.authz.ReasonCode;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Privacy-minimized decision evidence. Detail keys matching secret-like
 * names are dropped and values truncated before anything reaches the
 * database. Writes join the caller's transaction: if the audit row cannot
 * commit, the business write rolls back with it.
 */
@Service
public class AuditService {

  static final int MAX_VALUE_CHARS = 500;

  private static final Pattern SENSITIVE_KEY =
      Pattern.compile(
          ".*(password|passwd|secret|token|api[_-]?key|private[_-]?key|ssn|social[_-]?security"
              + "|dob|birth|passport|credential_|proof_|jwk|seed|mnemonic).*",
          Pattern.CASE_INSENSITIVE);

  private final AuditEventRepository events;
  private final ObjectMapper mapper;

  public AuditService(AuditEventRepository events, ObjectMapper mapper) {
    this.events = events;
    this.mapper = mapper;
  }

  @Transactional
  public void record(
      ServiceAccountPrincipal actor,
      Action action,
      ResourceRef resource,
      Decision decision,
      String correlationId,
      Map<String, String> detail) {
    String decisionText = decision.permitted() ? "PERMIT" : "DENY";
    events.insert(
        actor.tenantId(),
        "service_account",
        actor.id().toString(),
        action.name(),
        resource.type(),
        resource.id(),
        decisionText,
        decision.reasonCode(),
        decision.policyVersion(),
        correlationId == null ? "" : correlationId,
        toJson(sanitize(detail)));
  }

  /** Drops secret-like keys and truncates values; never throws on content. */
  Map<String, String> sanitize(Map<String, String> detail) {
    Map<String, String> clean = new LinkedHashMap<>();
    if (detail == null) {
      return clean;
    }
    for (Map.Entry<String, String> entry : detail.entrySet()) {
      String key = entry.getKey();
      if (key == null || SENSITIVE_KEY.matcher(key).matches()) {
        continue;
      }
      String value = entry.getValue();
      if (value != null && value.length() > MAX_VALUE_CHARS) {
        value = value.substring(0, MAX_VALUE_CHARS);
      }
      clean.put(key, value == null ? "" : value);
    }
    return clean;
  }

  private String toJson(Map<String, String> detail) {
    try {
      return mapper.writeValueAsString(detail);
    } catch (JacksonException e) {
      return "{}";
    }
  }

  /** Convenience overload for rejections without detail. */
  public void recordDenial(
      ServiceAccountPrincipal actor,
      Action action,
      ResourceRef resource,
      ReasonCode reasonCode,
      long policyVersion) {
    record(
        actor,
        action,
        resource,
        Decision.deny(reasonCode, policyVersion),
        "",
        Map.of());
  }
}
