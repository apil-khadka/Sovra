package dev.sovra.trust;

import tools.jackson.databind.JsonNode;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.web.CurrentPrincipal;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Trust registry endpoints. Reads are public federation metadata. */
@RestController
@RequestMapping("/api/trust")
public class TrustController {

  private final TrustService trust;

  public TrustController(TrustService trust) {
    this.trust = trust;
  }

  @GetMapping("/snapshots/current")
  public ResponseEntity<TrustService.SnapshotView> current() {
    return trust
        .currentSnapshot()
        .map(ResponseEntity::ok)
        .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).build());
  }

  @PostMapping("/proposals")
  public ResponseEntity<Map<String, String>> propose(@Valid @RequestBody ProposalRequest request) {
    var maker =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    TrustService.ProposalResult result =
        trust.propose(
            maker,
            new TrustService.ProposalInput(
                request.issuers().stream().map(IssuerRequest::toInput).toList(),
                request.policies().stream().map(PolicyRequest::toInput).toList()),
            request.note());
    return ResponseEntity.status(HttpStatus.CREATED)
        .body(
            Map.of(
                "version", String.valueOf(result.version()),
                "proposalId", result.proposalId().toString()));
  }

  @PostMapping("/proposals/{id}/approve")
  public ResponseEntity<Map<String, String>> approve(@PathVariable("id") UUID proposalId) {
    var checker =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    trust.approve(checker, proposalId);
    return ResponseEntity.ok(Map.of("proposalId", proposalId.toString()));
  }

  @PostMapping("/snapshots/{version}/activate")
  public ResponseEntity<Map<String, String>> activate(@PathVariable("version") long version) {
    var activator =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    trust.activate(activator, version);
    return ResponseEntity.ok(Map.of("version", String.valueOf(version)));
  }

  public record ProposalRequest(
      List<IssuerRequest> issuers, List<PolicyRequest> policies, String note) {
    public ProposalRequest {
      issuers = issuers == null ? List.of() : issuers;
      policies = policies == null ? List.of() : policies;
    }
  }

  public record IssuerRequest(
      @NotEmpty String issuerId,
      @NotEmpty String displayName,
      @NotEmpty String scope,
      @NotEmpty List<String> credentialTypes,
      @NotEmpty String keyId,
      @NotNull JsonNode publicKeyJwk,
      @NotNull Instant validFrom,
      @NotNull Instant validThrough,
      @NotEmpty String status) {

    TrustService.IssuerInput toInput() {
      return new TrustService.IssuerInput(
          issuerId, displayName, scope, credentialTypes, keyId, publicKeyJwk, validFrom,
          validThrough, status);
    }
  }

  public record PolicyRequest(
      @NotEmpty String rpId,
      @NotEmpty String purpose,
      @NotEmpty List<String> allowedTypes,
      @NotEmpty String maxAssurance) {

    TrustService.PolicyInput toInput() {
      return new TrustService.PolicyInput(rpId, purpose, allowedTypes, maxAssurance);
    }
  }
}
