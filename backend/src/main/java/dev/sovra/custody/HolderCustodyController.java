package dev.sovra.custody;

import dev.sovra.auth.CurrentPrincipal;
import dev.sovra.custody.HolderCustodyService.KeyView;
import dev.sovra.custody.HolderCustodyService.Recovered;
import dev.sovra.custody.HolderCustodyService.RecoveryView;
import dev.sovra.custody.HolderCustodyService.Reported;
import dev.sovra.web.Etags;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
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
 * Holder key custody desk (SOV-020, OD-09). Reports end a key's
 * authority at once; recovery activates a fresh proven key once
 * the live enrollment still qualifies. Reads stay metadata-only:
 * public keys and case state, never private material.
 */
@RestController
@RequestMapping("/api/holder-keys")
public class HolderCustodyController {

  private final HolderCustodyService custody;

  public HolderCustodyController(HolderCustodyService custody) {
    this.custody = custody;
  }

  public record ReportRequest(@NotBlank String thumbprint, @NotBlank String reason) {}

  public record RecoverRequest(
      @NotNull UUID recoveryId, @NotNull JsonNode newHolderJwk, String newKeyProof) {}

  @PostMapping("/report")
  public ResponseEntity<Map<String, Object>> report(@Valid @RequestBody ReportRequest request) {
    var caller = CurrentPrincipal.require();
    Reported reported = custody.report(caller, request.thumbprint(), request.reason());
    return ResponseEntity.ok(Map.of(
        "keyId", reported.keyId().toString(),
        "recoveryId", reported.recoveryId().toString(),
        "thumbprint", reported.thumbprint(),
        "revokedCredentials", reported.revokedCredentials()));
  }

  @PostMapping("/recover")
  public ResponseEntity<Map<String, Object>> recover(@Valid @RequestBody RecoverRequest request) {
    var caller = CurrentPrincipal.require();
    Recovered recovered = custody.recover(
        caller, request.recoveryId(), request.newHolderJwk(), request.newKeyProof());
    return ResponseEntity.ok(Map.of(
        "recoveryId", recovered.recoveryId().toString(),
        "newThumbprint", recovered.newThumbprint()));
  }

  @GetMapping("/{id}")
  public ResponseEntity<Map<String, Object>> get(
      @PathVariable("id") UUID id,
      @RequestHeader(value = "If-None-Match", required = false) String ifNoneMatch) {
    var caller = CurrentPrincipal.require();
    KeyView view = custody.read(caller, id);
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("keyId", view.keyId().toString());
    body.put("enrollmentId", view.enrollmentId().toString());
    body.put("thumbprint", view.thumbprint());
    body.put("status", view.status().name());
    body.put("createdBy", view.createdBy());
    List<Map<String, Object>> recoveries = new ArrayList<>();
    for (RecoveryView recovery : view.recoveries()) {
      Map<String, Object> entry = new LinkedHashMap<>();
      entry.put("recoveryId", recovery.recoveryId().toString());
      entry.put("reason", recovery.reason());
      entry.put("state", recovery.state().name());
      entry.put("newThumbprint", recovery.newThumbprint());
      recoveries.add(entry);
    }
    body.put("recoveries", recoveries);
    return Etags.respond(body, ifNoneMatch);
  }
}
