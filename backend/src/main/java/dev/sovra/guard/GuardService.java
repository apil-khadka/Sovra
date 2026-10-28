package dev.sovra.guard;

import dev.sovra.audit.AuditService;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ResourceRef;
import dev.sovra.issuance.TrustSnapshotProvider;
import dev.sovra.issuance.TrustUnavailableException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * Guard adjudication over live trust state (SOV-014). Builds the guard
 * context from the active trust snapshot — issuers with their standing,
 * epochs, and per-type claim scopes — plus the frozen G1 policy
 * documents, then runs the pure {@link PlanGuard}. Every call is
 * authorized and audited with a minimized verdict summary; the verdict
 * authorizes nothing by itself (INV-05), and consent still requires the
 * holder's explicit signed decision.
 */
@Service
public class GuardService {

  private final AuthorizationService authz;
  private final AuditService audit;
  private final TrustSnapshotProvider snapshots;
  private final Clock clock;

  public GuardService(
      AuthorizationService authz,
      AuditService audit,
      TrustSnapshotProvider snapshots,
      Clock clock) {
    this.authz = authz;
    this.audit = audit;
    this.snapshots = snapshots;
    this.clock = clock;
  }

  public record VerdictView(
      boolean accepted,
      GuardOutcome code,
      String reason,
      String rulesVersion,
      long snapshotVersion) {}

  /** Authorizes, adjudicates, and audits one candidate plan. */
  public VerdictView adjudicate(
      ServiceAccountPrincipal caller, CandidatePlan plan, SelectedPolicy selected) {
    ResourceRef resource =
        ResourceRef.tenantScoped("guard", "validations", caller.tenantId());
    Decision decision = authz.authorize(Optional.of(caller), Action.VALIDATE_PLAN, resource);
    if (!decision.permitted()) {
      audit.recordDenial(caller, Action.VALIDATE_PLAN, resource, decision.reasonCode(),
          decision.policyVersion());
      throw new ForbiddenException(decision.reasonCode());
    }
    var snapshot = snapshots.current().orElseThrow(TrustUnavailableException::new);
    GuardVerdict verdict =
        PlanGuard.validate(
            plan, context(snapshot), selected,
            new GuardInputs(PlanGuard.RULES_VERSION, clock.instant()));
    Map<String, String> detail = new LinkedHashMap<>();
    detail.put("accepted", String.valueOf(verdict.accepted()));
    detail.put("code", verdict.code().name());
    detail.put("snapshot", String.valueOf(snapshot.version()));
    detail.put("rules", PlanGuard.RULES_VERSION);
    audit.record(caller, Action.VALIDATE_PLAN, resource, decision, "", detail);
    return new VerdictView(
        verdict.accepted(), verdict.code(), verdict.reason(), PlanGuard.RULES_VERSION,
        snapshot.version());
  }

  private static GuardContext context(dev.sovra.trust.TrustService.SnapshotView snapshot) {
    Map<String, TrustedIssuer> issuers = new LinkedHashMap<>();
    for (var issuer : snapshot.issuers()) {
      List<String> claims = new ArrayList<>();
      for (String vct : issuer.credentialTypes()) {
        claims.addAll(GuardClaims.forType(vct));
      }
      // First row wins per issuer, matching the verifier's issuer
      // lookup; G1 snapshots carry one row per issuer.
      issuers.putIfAbsent(
          issuer.issuerId(),
          new TrustedIssuer(
              issuer.issuerId(), issuer.credentialTypes(), List.copyOf(claims),
              List.of(issuer.keyId()), issuer.status(), issuer.validFrom(),
              issuer.validThrough()));
    }
    return new GuardContext(Map.copyOf(issuers), GuardPolicies.documents());
  }
}
