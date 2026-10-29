package dev.sovra.audit;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ResourceRef;
import dev.sovra.authz.ReasonCode;
import java.util.Map;
import java.util.UUID;
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
    // Scope follows the resource, not the actor: global-resource
    // actions (trust registry) are platform evidence visible to every
    // tenant reader, so the chain of custody for a global change is
    // never fragmented across caller tenants. Tenant-scoped actions
    // keep actor attribution; their isolation is unchanged.
    UUID scope = resource.tenantId().isPresent() ? actor.tenantId() : null;
    events.insert(
        scope,
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
    return AuditSanitizer.sanitize(detail);
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

  /**
   * External-identity audit (BFF login/logout): the actor is an OIDC
   * subject, not a provisioned row yet. The caller sets the tenant
   * context first; RLS rejects anything unattributed, so failures
   * before tenant resolution stay log-only by schema design.
   */
  public void recordExternal(
      String actorType,
      java.util.UUID tenantId,
      String actorId,
      Action action,
      ResourceRef resource,
      Decision decision,
      String correlationId,
      Map<String, String> detail) {
    String decisionText = decision.permitted() ? "PERMIT" : "DENY";
    events.insert(
        tenantId,
        actorType,
        actorId,
        action.name(),
        resource.type(),
        resource.id(),
        decisionText,
        decision.reasonCode(),
        decision.policyVersion(),
        correlationId == null ? "" : correlationId,
        toJson(sanitize(detail)));
  }
}
