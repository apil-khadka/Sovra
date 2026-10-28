package dev.sovra.issuance;

import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.web.CurrentPrincipal;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;
import java.util.Map;
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
 * Credential issuance endpoints. Issuance requires an idempotency key;
 * replays return the original response byte-for-byte. Reads never
 * confirm or deny another tenant's objects (404 with an empty body).
 */
@RestController
@RequestMapping("/api/issuance")
public class CredentialController {

  private final IssuanceService issuance;

  public CredentialController(IssuanceService issuance) {
    this.issuance = issuance;
  }

  @PostMapping("/credentials")
  public ResponseEntity<String> issue(
      @RequestHeader("Idempotency-Key") String idempotencyKey,
      @Valid @RequestBody IssueRequest request) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    String response =
        issuance.issue(
            caller,
            new IssuanceService.IssueRequest(
                request.issuerId(), request.vct(), request.holderJwk(),
                request.holderProof(), request.claims(), request.expiresAt()),
            idempotencyKey);
    // Verbatim body: idempotent replays are byte-identical by construction.
    return ResponseEntity.status(HttpStatus.CREATED)
        .contentType(MediaType.APPLICATION_JSON)
        .body(response);
  }

  @GetMapping("/credentials/{id}")
  public ResponseEntity<IssuanceService.CredentialView> get(@PathVariable("id") UUID credentialId) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    return ResponseEntity.ok(issuance.get(caller, credentialId));
  }

  @GetMapping("/credentials/{id}/status")
  public ResponseEntity<IssuanceService.StatusView> status(@PathVariable("id") UUID credentialId) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    return ResponseEntity.ok(issuance.status(caller, credentialId));
  }

  @PostMapping("/credentials/{id}/revoke")
  public ResponseEntity<Map<String, String>> revoke(@PathVariable("id") UUID credentialId) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    IssuanceService.StatusView status = issuance.revoke(caller, credentialId);
    return ResponseEntity.ok(
        Map.of("credentialId", credentialId.toString(), "status", status.status()));
  }

  @GetMapping("/jwks.json")
  public ResponseEntity<String> jwks() {
    return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(issuance.jwks());
  }

  public record IssueRequest(
      @NotNull String issuerId,
      @NotNull String vct,
      @NotNull JsonNode holderJwk,
      @NotNull String holderProof,
      @NotNull Map<String, Object> claims,
      @NotNull Instant expiresAt) {}
}
