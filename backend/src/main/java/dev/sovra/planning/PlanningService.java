package dev.sovra.planning;

import dev.sovra.audit.AuditService;
import dev.sovra.audit.AuditedAuthorizer;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ResourceRef;
import dev.sovra.guard.CandidatePlan;
import dev.sovra.trust.TrustSnapshotProvider;
import dev.sovra.issuance.TrustUnavailableException;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * Planning orchestration (SOV-013, FR-04, FR-05). Authorizes the caller,
 * validates the intent before any model contact, then dispatches to the
 * live planner or the explicitly-labeled fixture planner. Every call is
 * authorized and audited with minimized provenance (mode, recommendation,
 * model, versions, budgets) — never intent PII or candidate content.
 */
@Service
public class PlanningService {

  private final AuthorizationService authz;
  private final AuditService audit;
  private final TrustSnapshotProvider snapshots;
  private final PlanningProperties properties;
  private final PlanningTools tools;
  private final LivePlanner live;
  private final Clock clock;

  public PlanningService(
      AuthorizationService authz,
      AuditService audit,
      TrustSnapshotProvider snapshots,
      PlanningProperties properties,
      PlanningTools tools,
      LivePlanner live,
      Clock clock) {
    this.authz = authz;
    this.audit = audit;
    this.snapshots = snapshots;
    this.properties = properties;
    this.tools = tools;
    this.live = live;
    this.clock = clock;
  }

  public record ProposalView(
      PlanningMode mode,
      boolean liveAcceptance,
      boolean synthetic,
      String profile,
      Map<String, Object> plan,
      String recommendation,
      String reason,
      String model,
      String promptVersion,
      String toolContractVersion,
      String toolSchemaHash,
      int toolCalls,
      long latencyMs,
      Long usageTokens,
      String cost,
      long snapshotVersion,
      List<String> scopeIssuerIds,
      List<String> scopeCredentialTypes,
      List<String> scopeJurisdictions) {}

  public record PolicyBindingView(String policyId, String policyVersion) {}

  public record StatusView(
      PlanningMode mode,
      boolean liveEnabled,
      boolean modelConfigured,
      String promptVersion,
      String toolContractVersion,
      String toolSchemaHash,
      String baselineVersion,
      List<String> tools,
      boolean discoveryScopeSupported,
      String schemaRegistryVersion,
      String guardRulesVersion,
      List<PolicyBindingView> supportedPolicyBindings) {}

  /** Authorizes, validates ahead of the model, plans, and audits. */
  public ProposalView propose(ServiceAccountPrincipal caller, PlanningIntent intent) {
    ResourceRef resource =
        ResourceRef.tenantScoped("planning", "proposals", caller.tenantId());
    Decision decision = AuditedAuthorizer.require(authz, audit, caller,
        Action.PROPOSE_PLAN, resource);
    var snapshot = snapshots.current().orElseThrow(TrustUnavailableException::new);
    String toolHash = PlanningVersions.toolSchemaHash(tools.callbacks());
    PlanningResult result;
    if (properties.liveEnabled()) {
      PlanningInvocation.install(
          new PlanningInvocation(
              caller, properties.maxToolCalls(), intent.scopeIssuerIds(),
              intent.scopeCredentialTypes(), intent.scopeJurisdictions()));
      try {
        result = live.plan(intent, toolHash);
      } finally {
        PlanningInvocation.clear();
      }
    } else {
      result = FixturePlanner.plan(intent, snapshot, clock.instant(), toolHash);
    }
    result = bindToScope(result, intent, snapshot);
    Map<String, String> detail = new LinkedHashMap<>();
    detail.put("mode", result.mode().name());
    detail.put("recommendation", result.recommendation().name());
    detail.put("model", result.model());
    detail.put("prompt", result.promptVersion());
    detail.put("tools", result.toolContractVersion());
    detail.put("toolCalls", String.valueOf(result.toolCalls()));
    detail.put("liveAcceptance", String.valueOf(result.liveAcceptance()));
    detail.put("scoped", String.valueOf(intent.scoped()));
    audit.record(caller, Action.PROPOSE_PLAN, resource, decision, "", detail);
    return view(result, intent, snapshot.version());
  }

  /** Planner status: liveness, readiness, and degradation stay distinct (FR-29). */
  public StatusView status(ServiceAccountPrincipal caller) {
    ResourceRef resource =
        ResourceRef.tenantScoped("planning", "status", caller.tenantId());
    Decision decision = AuditedAuthorizer.require(authz, audit, caller,
        Action.PROPOSE_PLAN, resource);
    Map<String, String> detail = new LinkedHashMap<>();
    detail.put("mode", properties.liveReady() ? PlanningMode.LIVE.name() : PlanningMode.FIXTURE.name());
    audit.record(caller, Action.PROPOSE_PLAN, resource, decision, "", detail);
    return new StatusView(
        properties.liveReady() ? PlanningMode.LIVE : PlanningMode.FIXTURE,
        properties.liveEnabled(),
        properties.credentialsPresent(),
        PlanningVersions.PROMPT_VERSION,
        PlanningVersions.TOOL_CONTRACT_VERSION,
        PlanningVersions.toolSchemaHash(tools.callbacks()),
        PlanningVersions.BASELINE_VERSION,
        live.toolNames(),
        true,
        dev.sovra.guard.ApprovedSchemas.version(),
        dev.sovra.guard.PlanGuard.RULES_VERSION,
        List.of(
            new PolicyBindingView(
                dev.sovra.guard.GuardPolicies.POLICY_ID,
                dev.sovra.guard.GuardPolicies.POLICY_VERSION),
            new PolicyBindingView(
                dev.sovra.guard.GuardPolicies.MAPPED_POLICY_ID,
                dev.sovra.guard.GuardPolicies.MAPPED_POLICY_VERSION)));
  }

  /**
   * Scope binding: a CANDIDATE_ONLY plan outside the intent's discovery
   * scope becomes NO_PATH (same mode/provenance, no plan). Scope only
   * narrows — an out-of-scope candidate is not rewritten into scope, it
   * is refused. Unscoped intents and non-candidates pass through unchanged.
   */
  static PlanningResult bindToScope(
      PlanningResult result,
      PlanningIntent intent,
      dev.sovra.trust.TrustService.SnapshotView snapshot) {
    if (result == null || !intent.scoped() || result.plan() == null
        || result.recommendation() != dev.sovra.guard.Recommendation.CANDIDATE_ONLY) {
      return result;
    }
    var plan = result.plan();
    if (!intent.scopeIssuerIds().isEmpty()
        && !intent.scopeIssuerIds().contains(plan.candidateIssuerId())) {
      return scopedOut(result);
    }
    if (!intent.scopeCredentialTypes().isEmpty()
        && !intent.scopeCredentialTypes().contains(plan.credentialType())) {
      return scopedOut(result);
    }
    if (!intent.scopeJurisdictions().isEmpty()) {
      var issuer = snapshot.issuers().stream()
          .filter(i -> plan.candidateIssuerId().equals(i.issuerId()))
          .findFirst().orElse(null);
      boolean hit = issuer != null && intent.scopeJurisdictions().stream()
          .anyMatch(hint -> issuer.scope() != null && issuer.scope().contains(hint));
      if (!hit) {
        return scopedOut(result);
      }
    }
    return result;
  }

  private static PlanningResult scopedOut(PlanningResult result) {
    return new PlanningResult(
        result.mode(), result.liveAcceptance(), result.synthetic(), result.profile(),
        null, dev.sovra.guard.Recommendation.NO_PATH,
        "candidate is outside the requested discovery scope",
        result.model(), result.promptVersion(), result.toolContractVersion(),
        result.toolSchemaHash(), result.toolCalls(), result.latencyMs(),
        result.usageTokens(), result.cost());
  }

  /**
   * Live-acceptance gate (SOV-035 demo rule): fixture results never
   * satisfy live acceptance. The evaluation harness and any live-evidence
   * consumer must pass agent results through here.
   */
  public PlanningResult requireLive(PlanningResult result) {
    if (result == null || !result.liveAcceptance() || result.mode() != PlanningMode.LIVE) {
      throw new InvalidPlanningException("fixture results never satisfy live acceptance");
    }
    return result;
  }

  private static ProposalView view(
      PlanningResult result, PlanningIntent intent, long snapshotVersion) {
    CandidatePlan plan = result.plan();
    return new ProposalView(
        result.mode(),
        result.liveAcceptance(),
        result.synthetic(),
        result.profile(),
        plan == null ? null : FixturePlanner.wire(plan),
        result.recommendation().name(),
        result.reason(),
        result.model(),
        result.promptVersion(),
        result.toolContractVersion(),
        result.toolSchemaHash(),
        result.toolCalls(),
        result.latencyMs(),
        result.usageTokens(),
        result.cost(),
        snapshotVersion,
        List.copyOf(intent.scopeIssuerIds()),
        List.copyOf(intent.scopeCredentialTypes()),
        List.copyOf(intent.scopeJurisdictions()));
  }
}
