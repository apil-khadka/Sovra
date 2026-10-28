package dev.sovra.consent;

import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.web.CurrentPrincipal;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;
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
import tools.jackson.databind.JsonNode;

/**
 * Consent-bound proof-request endpoints. The review shows the exact values
 * the holder's decision must sign; the presentation appears only while
 * consent is verified. Reads never confirm or deny another tenant's
 * objects (404 with an empty body).
 */
@RestController
@RequestMapping("/api/consent")
public class ConsentController {

  private final ConsentService consent;

  public ConsentController(ConsentService consent) {
    this.consent = consent;
  }

  @PostMapping("/requests")
  public ResponseEntity<ConsentService.RequestView> create(
      @Valid @RequestBody CreateRequest request) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    ConsentService.RequestView view =
        consent.create(
            caller,
            new ConsentService.CreateRequest(
                request.rpId(), request.audience(), request.purpose(),
                request.credentialId(), request.claims(), request.plan(),
                request.policyId(), request.policyVersion(), request.planHash(),
                request.challenge(), request.expiresAt()));
    return ResponseEntity.status(HttpStatus.CREATED).body(view);
  }

  @GetMapping("/requests/{id}")
  public ResponseEntity<ConsentService.RequestView> get(@PathVariable("id") UUID requestId) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    return ResponseEntity.ok(consent.get(caller, requestId));
  }

  @PostMapping("/requests/{id}/decision")
  public ResponseEntity<ConsentService.RequestView> decide(
      @PathVariable("id") UUID requestId, @Valid @RequestBody DecideRequest request) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    ConsentService.RequestView view =
        consent.decide(
            caller,
            requestId,
            new ConsentService.DecisionRequest(
                request.decision(), request.holderJwk(), request.consentProof()));
    return ResponseEntity.ok(view);
  }

  @GetMapping("/requests/{id}/presentation")
  public ResponseEntity<ConsentService.PresentationView> presentation(
      @PathVariable("id") UUID requestId) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    return ResponseEntity.ok(consent.presentation(caller, requestId));
  }

  public record CreateRequest(
      @NotNull String rpId,
      @NotNull String audience,
      @NotNull String purpose,
      @NotNull UUID credentialId,
      @NotNull Map<String, Object> claims,
      @NotNull JsonNode plan,
      @NotNull String policyId,
      @NotNull String policyVersion,
      @NotNull String planHash,
      @NotNull String challenge,
      @NotNull Instant expiresAt) {}

  public record DecideRequest(
      @NotNull String decision, @NotNull JsonNode holderJwk, @NotNull String consentProof) {}
}
