package dev.sovra.quarantine;

import dev.sovra.audit.AuditService;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.authz.ResourceRef;
import dev.sovra.config.DemoProperties;
import dev.sovra.vault.VaultCrypto;
import dev.sovra.vault.VaultEnvelope;
import dev.sovra.vault.VaultService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.HexFormat;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Hostile-image admission desk (SOV-017). Uploads seal into the vault
 * carrying the quarantine marker purpose — never readable through
 * the content endpoint — and wait for the isolated worker's
 * verdict. Promotion re-seals CLEAN bytes into a real vault object
 * server-side; callers never handle quarantine plaintext. Pending
 * or rejected output confers no authority (INV-09).
 */
@Service
public class QuarantineService {

  static final int MAX_ADMISSION_BYTES = 8 * 1024 * 1024;

  private final AuthorizationService authz;
  private final AuditService audit;
  private final VaultService vault;
  private final JdbcTemplate tenant;
  private final DemoProperties demo;

  public QuarantineService(
      AuthorizationService authz,
      AuditService audit,
      VaultService vault,
      JdbcTemplate tenantJdbcTemplate,
      DemoProperties demo) {
    this.authz = authz;
    this.audit = audit;
    this.vault = vault;
    this.tenant = tenantJdbcTemplate;
    this.demo = demo;
  }

  public record Admitted(
      UUID admissionId, UUID objectId, String status, String actualType, int sizeBytes) {}

  public record AdmissionView(
      UUID admissionId,
      UUID objectId,
      String status,
      String claimedType,
      String actualType,
      int sizeBytes,
      String contentSha256Hex,
      String verdict,
      Integer imageWidth,
      Integer imageHeight,
      Instant scannedAt,
      Instant createdAt) {}

  public record Promoted(UUID admissionId, UUID objectId, int version) {}

  @Transactional(noRollbackFor = ForbiddenException.class)
  public Admitted admit(
      ServiceAccountPrincipal caller, byte[] content, String claimedType, String issuerId) {
    Decision decision =
        require(caller, Action.QUARANTINE_ADMIT, "quarantine-admission", "admit");
    // After authorization (anonymous keeps 401), before validation:
    // an armed demo answers 403 even for malformed admissions.
    requireCallerIngestion();
    if (content == null || content.length == 0 || content.length > MAX_ADMISSION_BYTES) {
      throw new QuarantineInvalidException("content must be 1..8388608 bytes");
    }
    // Admission-time sniff is the cheap outer bound; the worker
    // re-verifies from sealed bytes and never trusts this verdict.
    String actual = QuarantineSniff.actualType(content)
        .orElseThrow(() -> new QuarantineInvalidException("actual file type is not allowlisted"));
    if (issuerId == null || issuerId.isBlank() || issuerId.length() > 512) {
      throw new QuarantineInvalidException("issuer id is required");
    }
    VaultService.StoredVersion stored = vault.store(caller, issuerId.trim(),
        "quarantine admission", List.of(VaultEnvelope.QUARANTINE_PURPOSE), content, null,
        VaultService.IngestionSource.CALLER);
    UUID admissionId = UUID.randomUUID();
    tenant.update(
        "INSERT INTO quarantine_admission (id, tenant_id, vault_object_id, claimed_type,"
            + " actual_type, size_bytes, content_sha256, created_by)"
            + " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        admissionId, caller.tenantId(), stored.objectId(),
        claimedType == null ? "" : claimedType, actual, content.length,
        VaultCrypto.sha256(content), caller.name());
    audit.record(
        caller, Action.QUARANTINE_ADMIT,
        ResourceRef.tenantScoped("quarantine-admission", admissionId.toString(),
            caller.tenantId()),
        decision, "",
        Map.of("object", stored.objectId().toString(), "actual-type", actual,
            "bytes", String.valueOf(content.length)));
    return new Admitted(admissionId, stored.objectId(), "QUARANTINED", actual, content.length);
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public AdmissionView get(ServiceAccountPrincipal caller, UUID admissionId) {
    Decision decision =
        require(caller, Action.QUARANTINE_READ, "quarantine-admission", admissionId.toString());
    AdmissionView view = load(admissionId);
    audit.record(
        caller, Action.QUARANTINE_READ,
        ResourceRef.tenantScoped("quarantine-admission", admissionId.toString(),
            caller.tenantId()),
        decision, "", Map.of("status", view.status()));
    return view;
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public Promoted promote(
      ServiceAccountPrincipal caller,
      UUID admissionId,
      UUID grantId,
      String purpose,
      String workload,
      List<String> purposes,
      String displayName) {
    Decision decision = require(caller, Action.QUARANTINE_PROMOTE, "quarantine-admission",
        admissionId.toString());
    AdmissionView admission = load(admissionId);
    if (!"CLEAN".equals(admission.status())) {
      throw new QuarantineConflictException(
          "admission is " + admission.status() + "; only CLEAN admissions promote");
    }
    if (purposes != null && purposes.contains(VaultEnvelope.QUARANTINE_PURPOSE)) {
      throw new QuarantineInvalidException("promoted purposes must be real purposes");
    }
    // Bytes open server-side under the quarantine grant and re-seal
    // into a fresh object; the caller never sees quarantine plaintext.
    // The issuer carries over from the sealed quarantine object.
    byte[] content = vault.readForQuarantine(
        caller, admission.objectId(), 1, grantId, purpose, workload);
    String issuerId = vault.metadata(caller, admission.objectId()).issuerId();
    VaultService.StoredVersion stored = vault.store(caller, issuerId,
        displayName == null ? "" : displayName,
        purposes == null ? List.of("enrollment-review") : purposes, content, null,
        VaultService.IngestionSource.SERVER);
    // Terminal transition guarded in the row, after the re-seal: a
    // bad grant fails above while the admission is still CLEAN (and
    // retryable), while a second promote of the same admission
    // conflicts here and rolls its duplicate re-seal back.
    int marked = tenant.update(
        "UPDATE quarantine_admission SET status = 'PROMOTED' WHERE id = ? AND status = 'CLEAN'",
        admissionId);
    if (marked == 0) {
      throw new QuarantineConflictException("admission was already promoted");
    }
    audit.record(
        caller, Action.QUARANTINE_PROMOTE,
        ResourceRef.tenantScoped("quarantine-admission", admissionId.toString(),
            caller.tenantId()),
        decision, "",
        Map.of("object", stored.objectId().toString(), "version",
            String.valueOf(stored.version())));
    return new Promoted(admissionId, stored.objectId(), stored.version());
  }

  private AdmissionView load(UUID admissionId) {
    List<AdmissionView> rows = tenant.query(
        "SELECT id, vault_object_id, status, claimed_type, actual_type, size_bytes,"
            + " content_sha256, verdict, image_width, image_height, scanned_at, created_at"
            + " FROM quarantine_admission WHERE id = ?",
        (rs, row) -> new AdmissionView(
            rs.getObject("id", UUID.class),
            rs.getObject("vault_object_id", UUID.class),
            rs.getString("status"),
            rs.getString("claimed_type"),
            rs.getString("actual_type"),
            rs.getInt("size_bytes"),
            HexFormat.of().formatHex(rs.getBytes("content_sha256")),
            rs.getString("verdict"),
            rs.getObject("image_width", Integer.class),
            rs.getObject("image_height", Integer.class),
            rs.getTimestamp("scanned_at") == null
                ? null : rs.getTimestamp("scanned_at").toInstant(),
            rs.getTimestamp("created_at").toInstant()),
        admissionId);
    if (rows.isEmpty()) {
      throw new QuarantineNotFoundException();
    }
    return rows.get(0);
  }

  private Decision require(
      ServiceAccountPrincipal caller, Action action, String type, String id) {
    Decision decision = authz.authorize(
        Optional.of(caller), action, ResourceRef.tenantScoped(type, id, caller.tenantId()));
    if (!decision.permitted()) {
      audit.recordDenial(
          caller, action, ResourceRef.tenantScoped(type, id, caller.tenantId()),
          decision.reasonCode(), decision.policyVersion());
      throw new ForbiddenException(decision.reasonCode());
    }
    return decision;
  }

  /**
   * Public-demo ingestion boundary (SOV-027). Enforcement lives in
   * the service — not the controller — so every present and future
   * caller path is fail-closed when the demo is armed.
   */
  private void requireCallerIngestion() {
    if (demo.syntheticOnly()) {
      throw new ForbiddenException(ReasonCode.DEMO_SYNTHETIC_ONLY);
    }
  }

}
