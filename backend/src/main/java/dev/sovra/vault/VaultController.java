package dev.sovra.vault;

import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.config.DemoProperties;
import dev.sovra.vault.VaultService.GrantView;
import dev.sovra.vault.VaultService.ObjectMetadata;
import dev.sovra.vault.VaultService.ReadResult;
import dev.sovra.vault.VaultService.StoredVersion;
import dev.sovra.vault.VaultService.VersionMetadata;
import dev.sovra.web.CurrentPrincipal;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
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
 * Encrypted local vault (SOV-016). Issuer workers seal source bytes
 * under per-version envelope AEAD; reads release plaintext only to a
 * live, exactly-matching grant. Responses never carry key material,
 * and reads never carry anything but the authorized version bytes.
 */
@RestController
@RequestMapping("/api/vault")
public class VaultController {

  private final VaultService vault;
  private final DemoProperties demo;

  public VaultController(VaultService vault, DemoProperties demo) {
    this.vault = vault;
    this.demo = demo;
  }

  public record StoreRequest(
      @NotBlank String issuerId,
      String displayName,
      @NotEmpty List<String> purposes,
      @NotBlank String contentBase64,
      String contentSha256Hex) {}

  public record VersionRequest(
      @NotEmpty List<String> purposes,
      @NotBlank String contentBase64,
      String contentSha256Hex) {}

  public record GrantRequest(
      @NotNull UUID objectId,
      int objectVersion,
      String principalType,
      UUID principalId,
      @NotBlank String purpose,
      @NotBlank String workload,
      long ttlSeconds) {}

  public record ReadRequest(
      @NotNull UUID grantId, @NotBlank String purpose, @NotBlank String workload) {}

  @PostMapping("/objects")
  public ResponseEntity<Map<String, Object>> store(@Valid @RequestBody StoreRequest request) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    requireCallerIngestion();
    StoredVersion stored = vault.store(
        caller,
        request.issuerId(),
        request.displayName(),
        request.purposes(),
        decode(request.contentBase64()),
        request.contentSha256Hex());
    return ResponseEntity.status(HttpStatus.CREATED)
        .body(Map.of("objectId", stored.objectId().toString(), "version", stored.version()));
  }

  @PostMapping("/objects/{id}/versions")
  public ResponseEntity<Map<String, Object>> storeVersion(
      @PathVariable("id") UUID id, @Valid @RequestBody VersionRequest request) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    requireCallerIngestion();
    StoredVersion stored = vault.storeVersion(
        caller, id, request.purposes(), decode(request.contentBase64()),
        request.contentSha256Hex());
    return ResponseEntity.status(HttpStatus.CREATED)
        .body(Map.of(
            "objectId", stored.objectId().toString(), "version", stored.version()));
  }

  @GetMapping("/objects/{id}")
  public ResponseEntity<Map<String, Object>> metadata(@PathVariable("id") UUID id) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    ObjectMetadata found = vault.metadata(caller, id);
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("objectId", found.objectId().toString());
    body.put("issuerId", found.issuerId());
    body.put("displayName", found.displayName());
    body.put("versions", found.versions().stream().map(VaultController::versionView).toList());
    return ResponseEntity.ok(body);
  }

  @PostMapping("/grants")
  public ResponseEntity<Map<String, Object>> grant(@Valid @RequestBody GrantRequest request) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    GrantView granted = vault.grant(
        caller,
        request.objectId(),
        request.objectVersion(),
        request.principalType() == null ? "service_account" : request.principalType(),
        request.principalId() == null ? caller.id() : request.principalId(),
        request.purpose(),
        request.workload(),
        request.ttlSeconds());
    return ResponseEntity.status(HttpStatus.CREATED).body(grantView(granted));
  }

  @PostMapping("/grants/{id}/revoke")
  public ResponseEntity<Map<String, Object>> revoke(@PathVariable("id") UUID id) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    return ResponseEntity.ok(grantView(vault.revokeGrant(caller, id)));
  }

  @PostMapping("/objects/{id}/versions/{version}/read")
  public ResponseEntity<Map<String, Object>> read(
      @PathVariable("id") UUID id,
      @PathVariable("version") int version,
      @Valid @RequestBody ReadRequest request) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    ReadResult result = vault.read(
        caller, id, version, request.grantId(), request.purpose(), request.workload());
    return ResponseEntity.ok(Map.of(
        "objectId", id.toString(),
        "version", result.version(),
        "contentSha256Hex", result.contentSha256Hex(),
        "contentBase64", Base64.getEncoder().encodeToString(result.content())));
  }

  @PostMapping("/keys/rotate")
  public ResponseEntity<Map<String, Object>> rotateKek() {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    return ResponseEntity.ok(Map.of("kekVersion", vault.rotateKek(caller)));
  }

  @PostMapping("/objects/{id}/versions/{version}/delete")
  public ResponseEntity<Map<String, Object>> delete(
      @PathVariable("id") UUID id, @PathVariable("version") int version) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    vault.deleteVersion(caller, id, version);
    return ResponseEntity.ok(
        Map.of("objectId", id.toString(), "version", version, "status", "DELETED"));
  }

  private static Map<String, Object> versionView(VersionMetadata version) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("version", version.version());
    body.put("purposes", version.purposes());
    body.put("kekVersion", version.kekVersion());
    body.put("status", version.status());
    body.put("contentSha256Hex", version.contentSha256Hex());
    body.put("createdAt", version.createdAt().toString());
    return body;
  }

  private static Map<String, Object> grantView(GrantView grant) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("grantId", grant.grantId().toString());
    body.put("objectId", grant.objectId().toString());
    body.put("objectVersion", grant.objectVersion());
    body.put("principalType", grant.principalType());
    body.put("principalId", grant.principalId().toString());
    body.put("purpose", grant.purpose());
    body.put("workload", grant.workload());
    body.put("revoked", grant.revoked());
    body.put("expiresAt", grant.expiresAt().toString());
    body.put("createdAt", grant.createdAt().toString());
    return body;
  }

  private void requireCallerIngestion() {
    if (demo.syntheticOnly()) {
      throw new ForbiddenException(ReasonCode.DEMO_SYNTHETIC_ONLY);
    }
  }

  private static byte[] decode(String base64) {
    try {
      return Base64.getDecoder().decode(base64);
    } catch (IllegalArgumentException e) {
      throw new VaultInvalidException("content is not base64");
    }
  }
}
