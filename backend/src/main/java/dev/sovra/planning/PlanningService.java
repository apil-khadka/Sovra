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
      long snapshotVersion) {}

  public record StatusView(
      PlanningMode mode,
      boolean liveEnabled,
      boolean modelConfigured,
      String promptVersion,
      String toolContractVersion,
      String toolSchemaHash,
      String baselineVersion,
      List<String> tools) {}

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
          new PlanningInvocation(caller, properties.maxToolCalls()));
      try {
        result = live.plan(intent, toolHash);
      } finally {
        PlanningInvocation.clear();
      }
    } else {
      result = FixturePlanner.plan(intent, snapshot, clock.instant(), toolHash);
    }
    Map<String, String> detail = new LinkedHashMap<>();
    detail.put("mode", result.mode().name());
    detail.put("recommendation", result.recommendation().name());
    detail.put("model", result.model());
    detail.put("prompt", result.promptVersion());
    detail.put("tools", result.toolContractVersion());
    detail.put("toolCalls", String.valueOf(result.toolCalls()));
    detail.put("liveAcceptance", String.valueOf(result.liveAcceptance()));
    audit.record(caller, Action.PROPOSE_PLAN, resource, decision, "", detail);
    return view(result, snapshot.version());
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
        live.toolNames());
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

  private static ProposalView view(PlanningResult result, long snapshotVersion) {
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
        snapshotVersion);
  }
}
