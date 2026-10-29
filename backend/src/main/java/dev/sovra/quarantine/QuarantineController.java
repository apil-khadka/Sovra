package dev.sovra.quarantine;

import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.config.DemoProperties;
import dev.sovra.quarantine.QuarantineService.AdmissionView;
import dev.sovra.quarantine.QuarantineService.Admitted;
import dev.sovra.quarantine.QuarantineService.Promoted;
import dev.sovra.web.CurrentPrincipal;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.Base64;
import java.util.LinkedHashMap;
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

/**
 * Hostile-image admission desk (SOV-017). Uploads seal into encrypted
 * quarantine for the isolated worker; verdicts and promotion stay
 * metadata-only — no endpoint serves quarantine bytes.
 */
@RestController
@RequestMapping("/api/quarantine")
public class QuarantineController {

  private final QuarantineService quarantine;
  private final DemoProperties demo;

  public QuarantineController(QuarantineService quarantine, DemoProperties demo) {
    this.quarantine = quarantine;
    this.demo = demo;
  }

  public record AdmitRequest(
      @NotBlank String contentBase64, String claimedType, @NotBlank String issuerId) {}

  public record PromoteRequest(
      @NotNull UUID grantId,
      @NotBlank String purpose,
      @NotBlank String workload,
      List<String> purposes,
      String displayName) {}

  @PostMapping("/admissions")
  public ResponseEntity<Map<String, Object>> admit(@Valid @RequestBody AdmitRequest request) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    if (demo.syntheticOnly()) {
      throw new ForbiddenException(ReasonCode.DEMO_SYNTHETIC_ONLY);
    }
    Admitted admitted = quarantine.admit(
        caller, decode(request.contentBase64()), request.claimedType(), request.issuerId());
    return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of(
        "admissionId", admitted.admissionId().toString(),
        "objectId", admitted.objectId().toString(),
        "status", admitted.status(),
        "actualType", admitted.actualType(),
        "sizeBytes", admitted.sizeBytes()));
  }

  @GetMapping("/admissions/{id}")
  public ResponseEntity<Map<String, Object>> get(@PathVariable("id") UUID id) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    AdmissionView view = quarantine.get(caller, id);
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("admissionId", view.admissionId().toString());
    body.put("objectId", view.objectId().toString());
    body.put("status", view.status());
    body.put("claimedType", view.claimedType());
    body.put("actualType", view.actualType());
    body.put("sizeBytes", view.sizeBytes());
    body.put("contentSha256Hex", view.contentSha256Hex());
    body.put("verdict", view.verdict());
    body.put("imageWidth", view.imageWidth());
    body.put("imageHeight", view.imageHeight());
    body.put("scannedAt", view.scannedAt() == null ? null : view.scannedAt().toString());
    body.put("createdAt", view.createdAt().toString());
    return ResponseEntity.ok(body);
  }

  @PostMapping("/admissions/{id}/promote")
  public ResponseEntity<Map<String, Object>> promote(
      @PathVariable("id") UUID id, @Valid @RequestBody PromoteRequest request) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    Promoted promoted = quarantine.promote(caller, id, request.grantId(), request.purpose(),
        request.workload(), request.purposes(), request.displayName());
    return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
        "admissionId", promoted.admissionId().toString(),
        "objectId", promoted.objectId().toString(),
        "version", promoted.version()));
  }

  private static byte[] decode(String base64) {
    try {
      return Base64.getDecoder().decode(base64);
    } catch (IllegalArgumentException e) {
      throw new QuarantineInvalidException("content is not base64");
    }
  }
}
