package dev.sovra.bff;

import dev.sovra.consent.ConsentController;
import dev.sovra.consent.ConsentService;
import dev.sovra.verification.VerificationController;
import dev.sovra.verification.VerificationService;
import dev.sovra.auth.CurrentPrincipal;
import dev.sovra.web.Etags;
import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Session-chain holder journey (SOV-006, SOV-041 browser path): the
 * same consent review/decide/presentation and verification
 * submit/read services behind BFF sessions, so a human in a browser
 * acts as themselves instead of pasting a Bearer [REDACTED] Authority
 * checks are identical on both chains; holder actions stay
 * signature-gated (consent proof, binding proof) either way.
 * Issuance and request creation stay machine-only: they are
 * back-office operations, not holder actions.
 */
@RestController
@RequestMapping("/api/bff")
@ConditionalOnProperty(name = "sovra.bff.enabled", havingValue = "true")
public class BffHolderController {

  private final ConsentService consent;
  private final VerificationService verification;

  public BffHolderController(ConsentService consent, VerificationService verification) {
    this.consent = consent;
    this.verification = verification;
  }

  @GetMapping("/consent/requests/{id}")
  public ResponseEntity<ConsentService.RequestView> review(
      @PathVariable("id") UUID requestId,
      @RequestHeader(value = "If-None-Match", required = false) String ifNoneMatch) {
    var caller =
        CurrentPrincipal.require();
    ConsentService.RequestView view = consent.get(caller, requestId);
    return Etags.respond(view, ifNoneMatch);
  }

  @PostMapping("/consent/requests/{id}/decision")
  public ResponseEntity<ConsentService.RequestView> decide(
      @PathVariable("id") UUID requestId,
      @Valid @RequestBody ConsentController.DecideRequest request) {
    var caller =
        CurrentPrincipal.require();
    ConsentService.RequestView view =
        consent.decide(
            caller,
            requestId,
            new ConsentService.DecisionRequest(
                request.decision(), request.holderJwk(), request.consentProof()));
    return ResponseEntity.ok(view);
  }

  @GetMapping("/consent/requests/{id}/presentation")
  public ResponseEntity<ConsentService.PresentationView> presentation(
      @PathVariable("id") UUID requestId) {
    var caller =
        CurrentPrincipal.require();
    return ResponseEntity.ok(consent.presentation(caller, requestId));
  }

  @PostMapping("/verification/presentations")
  public ResponseEntity<String> verify(
      @Valid @RequestBody VerificationController.VerifyRequest request) {
    var caller =
        CurrentPrincipal.require();
    String response =
        verification.verify(
            caller,
            new VerificationService.VerifyRequest(
                request.requestId(), request.nonce(), request.audience(),
                request.holderJwk(), request.bindingProof()));
    return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(response);
  }

  @GetMapping("/verification/decisions/{id}")
  public ResponseEntity<VerificationService.DecisionView> decision(
      @PathVariable("id") UUID decisionId,
      @RequestHeader(value = "If-None-Match", required = false) String ifNoneMatch) {
    var caller =
        CurrentPrincipal.require();
    VerificationService.DecisionView view = verification.get(caller, decisionId);
    return Etags.respond(view, ifNoneMatch);
  }
}
