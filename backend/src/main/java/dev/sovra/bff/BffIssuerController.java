package dev.sovra.bff;

import dev.sovra.audit.AuditCursor;
import dev.sovra.audit.AuditEventRepository;
import dev.sovra.audit.AuditService;
import dev.sovra.audit.AuditedAuthorizer;
import dev.sovra.auth.CurrentPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.ResourceRef;
import dev.sovra.enrollment.EnrollmentController;
import dev.sovra.extraction.ExtractionController;
import dev.sovra.issuance.CredentialController;
import dev.sovra.issuance.IssuanceService;
import dev.sovra.vault.VaultInvalidException;
import dev.sovra.vault.VaultService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Issuer information-management desk (SOV-023): extraction
 * queues, corrections, approvals, enrollment intake/review, and
 * credential status behind BFF sessions, so issuer operators in a
 * browser act as themselves. Casework calls delegate to the
 * machine controllers — one wire shape on both chains, so the
 * desk can never drift from the published API. Original-image
 * viewing stays purpose-bound: each view mints a short,
 * audit-logged grant for exactly this reviewer and refuses
 * anything that is not a PNG or JPEG by magic bytes.
 */
@RestController
@RequestMapping("/api/bff/issuer")
@ConditionalOnProperty(name = "sovra.bff.enabled", havingValue = "true")
public class BffIssuerController {

  static final String REVIEW_PURPOSE = "issuer-review";
  static final String REVIEW_WORKLOAD = "issuer-desk";
  static final long REVIEW_GRANT_TTL_SECONDS = 300;

  static final List<String> ISSUER_AUDIT_ACTIONS =
      List.of(
          "EXTRACTION_RUN",
          "EXTRACTION_CORRECT",
          "EXTRACTION_APPROVE",
          "EXTRACTION_READ",
          "ENROLLMENT_CREATE",
          "ENROLLMENT_SUBMIT",
          "ENROLLMENT_DECIDE",
          "ENROLLMENT_READ",
          "ISSUE_CREDENTIAL",
          "READ_CREDENTIAL",
          "VAULT_STORE_OBJECT",
          "VAULT_READ_OBJECT",
          "VAULT_READ_METADATA",
          "VAULT_GRANT_ACCESS",
          "VAULT_REVOKE_GRANT",
          "QUARANTINE_ADMIT",
          "QUARANTINE_READ",
          "QUARANTINE_PROMOTE",
          "HOLDER_REPORT",
          "HOLDER_READ");

  private final ExtractionController extraction;
  private final EnrollmentController enrollment;
  private final CredentialController credentials;
  private final VaultService vault;
  private final AuthorizationService authz;
  private final AuditService audit;
  private final AuditEventRepository events;

  public BffIssuerController(
      ExtractionController extraction,
      EnrollmentController enrollment,
      CredentialController credentials,
      VaultService vault,
      AuthorizationService authz,
      AuditService audit,
      AuditEventRepository events) {
    this.extraction = extraction;
    this.enrollment = enrollment;
    this.credentials = credentials;
    this.vault = vault;
    this.authz = authz;
    this.audit = audit;
    this.events = events;
  }

  public record ReviewViewRequest(@NotNull UUID objectId, @Min(1) int version) {}

  @GetMapping("/extraction/records")
  public ResponseEntity<Map<String, Object>> extractionQueue(
      @RequestParam(required = false) String state,
      @RequestParam(defaultValue = "50") int limit,
      @RequestParam(required = false) String cursor) {
    return extraction.list(state, limit, cursor);
  }

  @GetMapping("/extraction/records/{id}")
  public ResponseEntity<Map<String, Object>> extractionRecord(
      @PathVariable("id") UUID id,
      @RequestHeader(value = "If-None-Match", required = false) String ifNoneMatch) {
    return extraction.get(id, ifNoneMatch);
  }

  @PostMapping("/extraction/records/{id}/revisions")
  public ResponseEntity<Map<String, Object>> correct(
      @PathVariable("id") UUID id,
      @Valid @RequestBody ExtractionController.CorrectRequest request) {
    return extraction.correct(id, request);
  }

  @PostMapping("/extraction/records/{id}/approval")
  public ResponseEntity<Map<String, Object>> approveExtraction(
      @PathVariable("id") UUID id,
      @Valid @RequestBody ExtractionController.ApproveRequest request) {
    return extraction.approve(id, request);
  }

  @PostMapping("/enrollments")
  public ResponseEntity<Map<String, Object>> createEnrollment(
      @Valid @RequestBody EnrollmentController.CreateRequest request) {
    return enrollment.create(request);
  }

  @GetMapping("/enrollments")
  public ResponseEntity<Map<String, Object>> enrollmentQueue(
      @RequestParam(required = false) String state,
      @RequestParam(defaultValue = "50") int limit,
      @RequestParam(required = false) String cursor) {
    return enrollment.list(state, limit, cursor);
  }

  @GetMapping("/enrollments/{id}")
  public ResponseEntity<Map<String, Object>> enrollmentCase(
      @PathVariable("id") UUID id,
      @RequestHeader(value = "If-None-Match", required = false) String ifNoneMatch) {
    return enrollment.get(id, ifNoneMatch);
  }

  @PostMapping("/enrollments/{id}/submit")
  public ResponseEntity<Map<String, Object>> submit(@PathVariable("id") UUID id) {
    return enrollment.submit(id);
  }

  @PostMapping("/enrollments/{id}/decision")
  public ResponseEntity<Map<String, Object>> decide(
      @PathVariable("id") UUID id,
      @Valid @RequestBody EnrollmentController.DecideRequest request) {
    return enrollment.decide(id, request);
  }

  @GetMapping("/credentials/{id}")
  public ResponseEntity<IssuanceService.CredentialView> credential(@PathVariable("id") UUID id) {
    return credentials.get(id);
  }

  @GetMapping("/credentials/{id}/status")
  public ResponseEntity<IssuanceService.StatusView> credentialStatus(@PathVariable("id") UUID id) {
    return credentials.status(id);
  }

  @PostMapping("/credentials/{id}/revoke")
  public ResponseEntity<Map<String, String>> revokeCredential(@PathVariable("id") UUID id) {
    return credentials.revoke(id);
  }

  /**
   * Purpose-bound original viewing (SOV-023): mints a 5-minute
   * grant for exactly this reviewer, reads through the standard
   * grant path (quarantine-marked bytes stay refused there), and
   * serves the bytes only when they are a PNG or JPEG by magic
   * bytes — stored type claims are never trusted.
   */
  @PostMapping("/vault/review-view")
  public ResponseEntity<Map<String, Object>> reviewView(
      @Valid @RequestBody ReviewViewRequest request) {
    var caller = CurrentPrincipal.require();
    VaultService.GrantView grant =
        vault.grant(
            caller,
            request.objectId(),
            request.version(),
            "human_membership",
            caller.id(),
            REVIEW_PURPOSE,
            REVIEW_WORKLOAD,
            REVIEW_GRANT_TTL_SECONDS);
    VaultService.ReadResult read =
        vault.read(
            caller,
            request.objectId(),
            request.version(),
            grant.grantId(),
            REVIEW_PURPOSE,
            REVIEW_WORKLOAD);
    String contentType = sniffImage(read.content());
    if (contentType == null) {
      vault.revokeGrant(caller, grant.grantId());
      throw new VaultInvalidException("original is not a reviewable image");
    }
    return ResponseEntity.ok(
        Map.of(
            "objectId", request.objectId().toString(),
            "version", read.version(),
            "contentType", contentType,
            "contentBase64", Base64.getEncoder().encodeToString(read.content()),
            "sha256Hex", read.contentSha256Hex()));
  }

  /** Issuer-scoped audit tail: casework actions only. */
  @GetMapping("/audit/events")
  public ResponseEntity<List<Map<String, Object>>> audit(
      @RequestParam(defaultValue = "50") int limit,
      @RequestParam(required = false) String cursor) {
    var principal = CurrentPrincipal.require();
    AuditedAuthorizer.require(
        authz,
        audit,
        principal,
        Action.READ_ISSUER_AUDIT,
        ResourceRef.tenantScoped("audit", "events", principal.tenantId()));
    AuditCursor position = cursor == null ? null : AuditCursor.decode(cursor);
    return ResponseEntity.ok(
        events.listIssuerActions(principal.tenantId(), limit, position, ISSUER_AUDIT_ACTIONS));
  }

  private String sniffImage(byte[] content) {
    if (content.length >= 8
        && content[0] == (byte) 0x89
        && content[1] == 0x50
        && content[2] == 0x4E
        && content[3] == 0x47
        && content[4] == 0x0D
        && content[5] == 0x0A
        && content[6] == 0x1A
        && content[7] == 0x0A) {
      return "image/png";
    }
    if (content.length >= 3
        && content[0] == (byte) 0xFF
        && content[1] == (byte) 0xD8
        && content[2] == (byte) 0xFF) {
      return "image/jpeg";
    }
    return null;
  }
}
