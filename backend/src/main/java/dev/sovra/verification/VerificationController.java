package dev.sovra.verification;

import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.web.CurrentPrincipal;
import dev.sovra.web.Etags;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.JsonNode;

/**
 * Verification endpoints. Every well-formed submission evaluates to a
 * durable decision — ACCEPTED, REJECTED, or UNKNOWN — returned with
 * 200; only a malformed envelope is a 400. Replays return the
 * original response byte-for-byte. Reads never confirm or deny
 * another tenant's objects (404 with an empty body).
 */
@RestController
@RequestMapping("/api/verification")
public class VerificationController {

  private final VerificationService verification;

  public VerificationController(VerificationService verification) {
    this.verification = verification;
  }

  @PostMapping("/presentations")
  public ResponseEntity<String> verify(@Valid @RequestBody VerifyRequest request) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    String response =
        verification.verify(
            caller,
            new VerificationService.VerifyRequest(
                request.requestId(), request.nonce(), request.audience(),
                request.holderJwk(), request.bindingProof()));
    // Verbatim body: replays are byte-identical by construction.
    return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(response);
  }

  @GetMapping("/decisions/{id}")
  public ResponseEntity<VerificationService.DecisionView> get(
      @PathVariable("id") UUID decisionId,
      @RequestHeader(value = "If-None-Match", required = false) String ifNoneMatch) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    VerificationService.DecisionView view = verification.get(caller, decisionId);
    // Decisions are immutable, so the tag is stable for the row's life.
    String etag = Etags.strong(view.toString());
    if (Etags.matches(etag, ifNoneMatch)) {
      return ResponseEntity.status(HttpStatus.NOT_MODIFIED).eTag(etag).build();
    }
    return ResponseEntity.ok().eTag(etag).body(view);
  }

  public record VerifyRequest(
      @NotNull UUID requestId,
      @NotNull String nonce,
      @NotNull String audience,
      @NotNull JsonNode holderJwk,
      @NotNull String bindingProof) {}
}
