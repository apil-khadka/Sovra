package dev.sovra.enrollment;

import dev.sovra.audit.AuditService;
import dev.sovra.audit.AuditedAuthorizer;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ResourceRef;
import dev.sovra.crypto.HolderProofException;
import dev.sovra.crypto.HolderProofs;
import dev.sovra.extraction.ExtractionService;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Enrollment review with maker/checker separation (SOV-019, OD-14).
 * An enrollment binds one approved extraction revision to one
 * opaque subject reference and one holder key. The creator
 * (maker) can never approve (FR-37); approvals pin the current
 * extraction head, so a later correction invalidates eligibility
 * until re-review (FR-38, INV-10). Eligibility answers the
 * issuance gate: only current approved enrollments authorize
 * signing, and only for their reviewed claims (FR-39).
 */
@Service
public class EnrollmentService {

  static final String BINDING_LABEL = "enrollment-binding";

  private final AuthorizationService authz;
  private final AuditService audit;
  private final ExtractionService extraction;
  private final JdbcTemplate tenant;
  private final ObjectMapper mapper;
  private final Clock clock;

  public EnrollmentService(
      AuthorizationService authz,
      AuditService audit,
      ExtractionService extraction,
      JdbcTemplate tenantJdbcTemplate,
      ObjectMapper mapper,
      Clock clock) {
    this.authz = authz;
    this.audit = audit;
    this.extraction = extraction;
    this.tenant = tenantJdbcTemplate;
    this.mapper = mapper;
    this.clock = clock;
  }

  public record Created(UUID enrollmentId, UUID subjectRef, EnrollmentState state) {}

  public record StateView(UUID enrollmentId, EnrollmentState state) {}

  public record DecisionView(UUID enrollmentId, EnrollmentState state, int boundRevision) {}

  public record EligibilityView(
      UUID enrollmentId, boolean eligible, String reason, Map<String, String> claims) {}

  public record ReviewView(
      int revision, String decision, boolean bindingProofOk, String reviewer) {}

  public record EnrollmentView(
      UUID enrollmentId,
      UUID subjectRef,
      UUID vaultObjectId,
      UUID extractionRecordId,
      int boundRevision,
      EnrollmentState state,
      String createdBy,
      String decidedBy,
      boolean eligible,
      String eligibilityReason,
      List<ReviewView> reviews) {}

  @Transactional(noRollbackFor = ForbiddenException.class)
  public Created create(
      ServiceAccountPrincipal caller,
      UUID vaultObjectId,
      UUID extractionRecordId,
      JsonNode holderJwk) {
    Decision decision =
        require(caller, Action.ENROLLMENT_CREATE, "enrollment", extractionRecordId.toString());
    if (vaultObjectId == null || extractionRecordId == null || holderJwk == null) {
      throw new EnrollmentInvalidException("source, extraction record, and holder key required");
    }
    ECPublicKey holderKey = holderKey(holderJwk);
    if (holderKey == null) {
      throw new EnrollmentInvalidException("holder key must be P-256");
    }
    ExtractionService.RecordView record = extraction.read(caller, extractionRecordId);
    if (!record.vaultObjectId().equals(vaultObjectId)) {
      throw new EnrollmentInvalidException("extraction record is for another source");
    }
    if (record.approvedRevision() == null) {
      // Unreviewed sources cannot seed enrollments (SEC-37).
      throw new EnrollmentConflictException("extraction revision is not approved");
    }
    UUID enrollmentId = UUID.randomUUID();
    UUID subjectRef = UUID.randomUUID();
    tenant.update(
        "INSERT INTO enrollment (id, tenant_id, subject_ref, vault_object_id,"
            + " extraction_record_id, bound_revision, holder_jwk, state, created_by_account,"
            + " created_by) VALUES (?, ?, ?, ?, ?, ?, ?::jsonb, 'PENDING', ?, ?)",
        enrollmentId,
        caller.tenantId(),
        subjectRef,
        vaultObjectId,
        extractionRecordId,
        record.approvedRevision(),
        writeJson(holderJwk),
        caller.id(),
        caller.name());
    audit.record(
        caller,
        Action.ENROLLMENT_CREATE,
        ResourceRef.tenantScoped("enrollment", enrollmentId.toString(), caller.tenantId()),
        decision,
        "",
        Map.of("revision", String.valueOf(record.approvedRevision())));
    return new Created(enrollmentId, subjectRef, EnrollmentState.PENDING);
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public StateView submit(ServiceAccountPrincipal caller, UUID enrollmentId) {
    Decision decision =
        require(caller, Action.ENROLLMENT_SUBMIT, "enrollment", enrollmentId.toString());
    EnrollmentRow row = enrollmentRow(enrollmentId);
    if (row.state == EnrollmentState.IN_REVIEW || row.state == EnrollmentState.REJECTED) {
      throw new EnrollmentConflictException("enrollment is not submittable");
    }
    if (row.state == EnrollmentState.APPROVED && !isStale(caller, row)) {
      // Current approvals stay put: re-review exists only for the
      // explicit refresh path after the source moves on (FR-38).
      throw new EnrollmentConflictException("enrollment approval is current");
    }
    tenant.update(
        "UPDATE enrollment SET state = 'IN_REVIEW' WHERE id = ?", enrollmentId);
    audit.record(
        caller,
        Action.ENROLLMENT_SUBMIT,
        ResourceRef.tenantScoped("enrollment", enrollmentId.toString(), caller.tenantId()),
        decision,
        "",
        Map.of());
    return new StateView(enrollmentId, EnrollmentState.IN_REVIEW);
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public DecisionView decide(
      ServiceAccountPrincipal caller,
      UUID enrollmentId,
      int revision,
      String decision,
      String bindingProof) {
    Decision authzDecision =
        require(caller, Action.ENROLLMENT_DECIDE, "enrollment", enrollmentId.toString());
    EnrollmentRow row = enrollmentRow(enrollmentId);
    if (row.state != EnrollmentState.IN_REVIEW) {
      throw new EnrollmentConflictException("enrollment is not in review");
    }
    if (caller.id().equals(row.createdByAccount)) {
      // Maker/checker (OD-14, FR-37): the identity that built the
      // case cannot approve it.
      throw new EnrollmentConflictException("self-approval is not permitted");
    }
    boolean approve;
    if ("approve".equals(decision)) {
      approve = true;
    } else if ("reject".equals(decision)) {
      approve = false;
    } else {
      throw new EnrollmentInvalidException("decision must be approve or reject");
    }
    ExtractionService.RecordView record = extraction.read(caller, row.extractionRecordId);
    if (record.approvedRevision() == null || revision != record.approvedRevision()) {
      // Revision-specific review (FR-37): only the current
      // approved head is decidable.
      throw new EnrollmentConflictException("revision is not the approved head");
    }
    boolean proofOk = false;
    if (approve) {
      ECPublicKey holderKey = holderKey(readJwk(row.holderJwk));
      verifyBinding(holderKey, bindingProof, enrollmentId, revision);
      proofOk = true;
    }
    EnrollmentState next = approve ? EnrollmentState.APPROVED : EnrollmentState.REJECTED;
    tenant.update(
        "UPDATE enrollment SET state = ?, bound_revision = ?, decided_by_account = ?,"
            + " decided_by = ?, decided_at = now() WHERE id = ?",
        next.name(), revision, caller.id(), caller.name(), enrollmentId);
    tenant.update(
        "INSERT INTO enrollment_review (tenant_id, enrollment_id, revision, decision,"
            + " binding_proof_ok, reviewer_account, reviewer)"
            + " VALUES (?, ?, ?, ?, ?, ?, ?)",
        caller.tenantId(),
        enrollmentId,
        revision,
        next.name(),
        proofOk,
        caller.id(),
        caller.name());
    audit.record(
        caller,
        Action.ENROLLMENT_DECIDE,
        ResourceRef.tenantScoped("enrollment", enrollmentId.toString(), caller.tenantId()),
        authzDecision,
        "",
        Map.of("state", next.name(), "revision", String.valueOf(revision)));
    return new DecisionView(enrollmentId, next, revision);
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public EnrollmentView read(ServiceAccountPrincipal caller, UUID enrollmentId) {
    Decision decision =
        require(caller, Action.ENROLLMENT_READ, "enrollment", enrollmentId.toString());
    EnrollmentRow row = enrollmentRow(enrollmentId);
    EligibilityView eligibility = eligibility(caller, row);
    List<ReviewView> reviews =
        tenant.query(
            "SELECT revision, decision, binding_proof_ok, reviewer FROM enrollment_review"
                + " WHERE enrollment_id = ? ORDER BY created_at, revision",
            (rs, n) -> new ReviewView(
                rs.getInt("revision"),
                rs.getString("decision"),
                rs.getBoolean("binding_proof_ok"),
                rs.getString("reviewer")),
            enrollmentId);
    audit.record(
        caller,
        Action.ENROLLMENT_READ,
        ResourceRef.tenantScoped("enrollment", enrollmentId.toString(), caller.tenantId()),
        decision,
        "",
        Map.of("state", row.state.name(), "eligible", String.valueOf(eligibility.eligible())));
    return new EnrollmentView(
        enrollmentId,
        row.subjectRef,
        row.vaultObjectId,
        row.extractionRecordId,
        row.boundRevision,
        row.state,
        row.createdBy,
        row.decidedBy,
        eligibility.eligible(),
        eligibility.reason(),
        reviews);
  }

  /**
   * Issuance-facing eligibility (FR-39): eligible only while the
   * enrollment is APPROVED and its bound revision is still the
   * extraction approved head. Claims are the reviewed normalized
   * fields — caller-supplied values never enter here. Audited as a
   * read; the issuance gate calls the same method.
   */
  @Transactional(noRollbackFor = ForbiddenException.class)
  public EligibilityView eligibilityFor(ServiceAccountPrincipal caller, UUID enrollmentId) {
    Decision decision =
        require(caller, Action.ENROLLMENT_READ, "enrollment", enrollmentId.toString());
    EligibilityView view = eligibility(caller, enrollmentRow(enrollmentId));
    audit.record(
        caller,
        Action.ENROLLMENT_READ,
        ResourceRef.tenantScoped("enrollment", enrollmentId.toString(), caller.tenantId()),
        decision,
        "",
        Map.of("eligible", String.valueOf(view.eligible()), "reason", view.reason()));
    return view;
  }

  /**
   * Issuance authorization (FR-37/39): returns the reviewed claims
   * only while the enrollment is APPROVED on the current head AND
   * the issuance holder key equals the enrolled key. Anything else
   * terminates, so obsolete approvals, unreviewed cases, and
   * key-substituted requests can never reach the signer.
   */
  @Transactional(noRollbackFor = ForbiddenException.class)
  public Map<String, String> issuanceClaims(
      ServiceAccountPrincipal caller, UUID enrollmentId, JsonNode holderJwk) {
    Decision decision =
        require(caller, Action.ENROLLMENT_READ, "enrollment", enrollmentId.toString());
    EnrollmentRow row = enrollmentRow(enrollmentId);
    EligibilityView view = eligibility(caller, row);
    if (!view.eligible()) {
      throw new EnrollmentConflictException("enrollment is " + view.reason().toLowerCase());
    }
    ECPublicKey enrolled = holderKey(readJwk(row.holderJwk));
    ECPublicKey offered;
    try {
      offered = HolderProofs.parseP256Key(holderJwk);
    } catch (HolderProofException e) {
      throw new EnrollmentInvalidException("issuance holder key is malformed");
    }
    String expected =
        dev.sovra.crypto.P256.thumbprint(
            enrolled.getW().getAffineX(), enrolled.getW().getAffineY());
    String actual =
        dev.sovra.crypto.P256.thumbprint(
            offered.getW().getAffineX(), offered.getW().getAffineY());
    if (!java.security.MessageDigest.isEqual(
        expected.getBytes(java.nio.charset.StandardCharsets.UTF_8),
        actual.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
      throw new EnrollmentConflictException("holder is not bound to this enrollment");
    }
    audit.record(
        caller,
        Action.ENROLLMENT_READ,
        ResourceRef.tenantScoped("enrollment", enrollmentId.toString(), caller.tenantId()),
        decision,
        "",
        Map.of("eligible", "true", "for", "issuance"));
    return view.claims();
  }

  private EligibilityView eligibility(ServiceAccountPrincipal caller, EnrollmentRow row) {
    if (row.state != EnrollmentState.APPROVED) {
      return new EligibilityView(row.id, false, "UNREVIEWED", Map.of());
    }
    ExtractionService.RecordView record = extraction.read(caller, row.extractionRecordId);
    if (record.approvedRevision() == null || record.approvedRevision() != row.boundRevision) {
      return new EligibilityView(row.id, false, "STALE_SOURCE", Map.of());
    }
    Map<String, String> claims = new TreeMap<>();
    for (ExtractionService.RevisionView revision : record.revisions()) {
      if (revision.revNo() == row.boundRevision) {
        claims.putAll(revision.normalized());
      }
    }
    // Derived permitted claim (FR-39): adult status comes from the
    // reviewed birth date, never from caller input. Missing or
    // unparseable dates omit the claim, failing issuance closed
    // while keeping eligibility itself computable.
    String birth = claims.get("date_of_birth");
    if (birth != null) {
      try {
        LocalDate day = LocalDate.parse(birth);
        claims.put(
            "adultOver18", String.valueOf(!day.plusYears(18).isAfter(LocalDate.now(clock))));
      } catch (java.time.format.DateTimeParseException e) {
        claims.remove("adultOver18");
      }
    }
    return new EligibilityView(row.id, true, "CURRENT", Map.copyOf(claims));
  }

  private boolean isStale(ServiceAccountPrincipal caller, EnrollmentRow row) {
    ExtractionService.RecordView record = extraction.read(caller, row.extractionRecordId);
    return record.approvedRevision() == null || record.approvedRevision() != row.boundRevision;
  }

  private void verifyBinding(
      ECPublicKey holderKey, String proof, UUID enrollmentId, int revision) {
    if (proof == null || proof.isBlank()) {
      throw new EnrollmentInvalidException("holder binding proof is required");
    }
    try {
      HolderProofs.verifyEs256(
          holderKey, proof, BINDING_LABEL + "\n" + enrollmentId + "\n" + revision, mapper);
    } catch (HolderProofException e) {
      throw new EnrollmentInvalidException("holder binding proof is invalid");
    }
  }

  private ECPublicKey holderKey(JsonNode jwk) {
    try {
      return HolderProofs.parseP256Key(jwk);
    } catch (HolderProofException e) {
      return null;
    }
  }

  private String writeJson(JsonNode node) {
    try {
      return mapper.writeValueAsString(node);
    } catch (Exception e) {
      throw new EnrollmentInvalidException("holder key is malformed");
    }
  }

  private JsonNode readJwk(String json) {
    try {
      return mapper.readTree(json);
    } catch (Exception e) {
      throw new IllegalStateException("stored holder key is not readable", e);
    }
  }

  private record EnrollmentRow(
      UUID id,
      UUID subjectRef,
      UUID vaultObjectId,
      UUID extractionRecordId,
      int boundRevision,
      String holderJwk,
      EnrollmentState state,
      UUID createdByAccount,
      String createdBy,
      String decidedBy) {}

  private EnrollmentRow enrollmentRow(UUID enrollmentId) {
    List<EnrollmentRow> rows =
        tenant.query(
            "SELECT id, subject_ref, vault_object_id, extraction_record_id, bound_revision,"
                + " holder_jwk, state, created_by_account, created_by, decided_by"
                + " FROM enrollment WHERE id = ?",
            (rs, n) -> new EnrollmentRow(
                rs.getObject("id", UUID.class),
                rs.getObject("subject_ref", UUID.class),
                rs.getObject("vault_object_id", UUID.class),
                rs.getObject("extraction_record_id", UUID.class),
                rs.getInt("bound_revision"),
                rs.getString("holder_jwk"),
                EnrollmentState.from(rs.getString("state")),
                rs.getObject("created_by_account", UUID.class),
                rs.getString("created_by"),
                rs.getString("decided_by")),
            enrollmentId);
    if (rows.isEmpty()) {
      throw new EnrollmentNotFoundException();
    }
    return rows.get(0);
  }

  private Decision require(
      ServiceAccountPrincipal caller, Action action, String type, String id) {
    return AuditedAuthorizer.require(
        authz, audit, caller, action, ResourceRef.tenantScoped(type, id, caller.tenantId()));
  }
}
