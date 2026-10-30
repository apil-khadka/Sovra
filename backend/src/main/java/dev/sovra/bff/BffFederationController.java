package dev.sovra.bff;

import dev.sovra.audit.AuditCursor;
import dev.sovra.audit.AuditEventRepository;
import dev.sovra.audit.AuditService;
import dev.sovra.audit.AuditedAuthorizer;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.authz.ResourceRef;
import dev.sovra.auth.CurrentPrincipal;
import dev.sovra.ops.AlertService;
import dev.sovra.trust.TrustController;
import dev.sovra.trust.TrustService;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Federation and security-operations desk (SOV-026): the same
 * trust review, audit evidence, and alert services behind BFF
 * sessions, so a trust admin in a browser acts as themselves.
 * Authority checks are identical on both chains; the dashboard
 * sees sanitized operational evidence only — no source bytes,
 * no keys, no decryption.
 */
@RestController
@RequestMapping("/api/bff")
@ConditionalOnProperty(name = "sovra.bff.enabled", havingValue = "true")
public class BffFederationController {

  private final TrustService trust;
  private final AuthorizationService authz;
  private final AuditService audit;
  private final AuditEventRepository events;
  private final AlertService alerts;

  public BffFederationController(
      TrustService trust,
      AuthorizationService authz,
      AuditService audit,
      AuditEventRepository events,
      AlertService alerts) {
    this.trust = trust;
    this.authz = authz;
    this.audit = audit;
    this.events = events;
    this.alerts = alerts;
  }

  @GetMapping("/trust/snapshots/current")
  public ResponseEntity<TrustService.SnapshotView> currentSnapshot() {
    CurrentPrincipal.require();
    return trust
        .currentSnapshot()
        .map(ResponseEntity::ok)
        .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).build());
  }

  @GetMapping("/trust/proposals")
  public ResponseEntity<List<TrustService.ProposalSummary>> proposals() {
    var caller =
        CurrentPrincipal.require();
    return ResponseEntity.ok(trust.listProposals(caller));
  }

  @PostMapping("/trust/proposals")
  public ResponseEntity<Map<String, String>> propose(
      @Valid @RequestBody TrustController.ProposalRequest request) {
    var maker =
        CurrentPrincipal.require();
    TrustService.ProposalResult result =
        trust.propose(
            maker,
            new TrustService.ProposalInput(
                request.issuers().stream().map(TrustController.IssuerRequest::toInput).toList(),
                request.policies().stream().map(TrustController.PolicyRequest::toInput).toList()),
            request.note());
    return ResponseEntity.status(HttpStatus.CREATED)
        .body(
            Map.of(
                "version", String.valueOf(result.version()),
                "proposalId", result.proposalId().toString()));
  }

  @PostMapping("/trust/proposals/{id}/approve")
  public ResponseEntity<Map<String, String>> approve(@PathVariable("id") UUID proposalId) {
    var checker =
        CurrentPrincipal.require();
    boolean personVerified = trust.approve(checker, proposalId);
    return ResponseEntity.ok(
        Map.of(
            "proposalId", proposalId.toString(),
            "personVerified", String.valueOf(personVerified)));
  }

  @PostMapping("/trust/snapshots/{version}/activate")
  public ResponseEntity<Map<String, String>> activate(@PathVariable("version") long version) {
    var activator =
        CurrentPrincipal.require();
    trust.activate(activator, version);
    return ResponseEntity.ok(Map.of("version", String.valueOf(version)));
  }

  @GetMapping("/audit/events")
  public ResponseEntity<List<Map<String, Object>>> audit(
      @RequestParam(defaultValue = "50") int limit,
      @RequestParam(required = false) String cursor) {
    var caller = CurrentPrincipal.get();
    var principal = caller.orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    AuditedAuthorizer.require(
        authz,
        audit,
        principal,
        Action.READ_AUDIT,
        ResourceRef.tenantScoped("audit", "events", principal.tenantId()));
    AuditCursor position = cursor == null ? null : AuditCursor.decode(cursor);
    return ResponseEntity.ok(events.listRecent(principal.tenantId(), limit, position));
  }

  @GetMapping("/alerts")
  public ResponseEntity<List<AlertService.Alert>> alerts() {
    var caller = CurrentPrincipal.get();
    var principal = caller.orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    AuditedAuthorizer.require(
        authz, audit, principal, Action.READ_ALERTS, ResourceRef.global("ops", "alerts"));
    return ResponseEntity.ok(alerts.active());
  }
}
