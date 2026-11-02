package dev.sovra.custody;

import dev.sovra.auth.CurrentPrincipal;
import dev.sovra.custody.HolderCustodyService.DeviceReported;
import dev.sovra.custody.HolderCustodyService.ReissuePlan;
import dev.sovra.custody.HolderCustodyService.ReissuePlanItem;
import dev.sovra.custody.HolderCustodyService.Reissued;
import dev.sovra.custody.HolderCustodyService.ReissuedCredential;
import dev.sovra.custody.HolderCustodyService.Reported;
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
import org.springframework.web.bind.annotation.RestController;

/**
 * Device custody and recovery-scoped reissuance (PROD-015). Theft
 * reports name the device; the service resolves it to its keys.
 * Reissue planning shows the exact credentials the report killed,
 * and reissuance replaces them under the recovery key — never by
 * resurrecting revoked ids.
 */
@RestController
public class HolderDeviceController {

  private final HolderCustodyService custody;

  public HolderDeviceController(HolderCustodyService custody) {
    this.custody = custody;
  }

  public record DeviceReportRequest(@NotNull UUID deviceId, @NotBlank String reason) {}

  public record ReissueRequest(Map<String, String> proofs) {}

  @PostMapping("/api/holder-devices/report")
  public ResponseEntity<Map<String, Object>> reportDevice(
      @Valid @RequestBody DeviceReportRequest request) {
    var caller = CurrentPrincipal.require();
    DeviceReported reported =
        custody.reportDevice(caller, request.deviceId(), request.reason());
    List<Map<String, Object>> cases = new ArrayList<>();
    for (Reported Case : reported.cases()) {
      cases.add(Map.of(
          "keyId", Case.keyId().toString(),
          "recoveryId", Case.recoveryId().toString(),
          "thumbprint", Case.thumbprint(),
          "revokedCredentials", Case.revokedCredentials()));
    }
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("deviceId", reported.deviceId().toString());
    body.put("status", reported.status());
    body.put("cases", cases);
    body.put("revokedCredentials", reported.revokedCredentials());
    return ResponseEntity.ok(body);
  }

  @GetMapping("/api/holder-recoveries/{id}/reissue-plan")
  public ResponseEntity<Map<String, Object>> reissuePlan(@PathVariable("id") UUID id) {
    var caller = CurrentPrincipal.require();
    ReissuePlan plan = custody.reissuePlan(caller, id);
    List<Map<String, Object>> items = new ArrayList<>();
    for (ReissuePlanItem item : plan.items()) {
      Map<String, Object> entry = new LinkedHashMap<>();
      entry.put("credentialId", item.credentialId().toString());
      entry.put("issuerId", item.issuerId());
      entry.put("vct", item.vct());
      entry.put("idempotencyKey", item.idempotencyKey());
      entry.put("reissuable", item.reissuable());
      entry.put("reason", item.reason());
      items.add(entry);
    }
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("recoveryId", plan.recoveryId().toString());
    body.put("enrollmentEligible", plan.enrollmentEligible());
    body.put("eligibilityReason", plan.eligibilityReason());
    body.put("items", items);
    return ResponseEntity.ok(body);
  }

  @PostMapping("/api/holder-recoveries/{id}/reissue")
  public ResponseEntity<Map<String, Object>> reissue(
      @PathVariable("id") UUID id, @RequestBody(required = false) ReissueRequest request) {
    var caller = CurrentPrincipal.require();
    Reissued reissued =
        custody.reissue(caller, id, request == null ? Map.of() : request.proofs());
    List<Map<String, Object>> credentials = new ArrayList<>();
    for (ReissuedCredential credential : reissued.credentials()) {
      credentials.add(Map.of(
          "oldCredentialId", credential.oldCredentialId().toString(),
          "newCredentialId", credential.newCredentialId().toString()));
    }
    return ResponseEntity.ok(Map.of(
        "recoveryId", reissued.recoveryId().toString(),
        "credentials", credentials));
  }
}
