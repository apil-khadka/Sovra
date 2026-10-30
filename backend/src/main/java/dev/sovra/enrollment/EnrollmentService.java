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
import dev.sovra.web.KeysetCursor;
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

  public record EnrollmentSummary(
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
      String createdAt) {}

  public record EnrollmentPage(List<EnrollmentSummary> items, String nextCursor) {}

  /**
   * Case queue (SOV-023): newest cases first, keyset-paged. State
   * filters the lifecycle — {@code pending}, {@code in_review},
   * {@code approved}, {@code rejected}, {@code all} default.
   * Eligibility mirrors {@link #eligibilityFor} (APPROVED on the
   * current approved head) in one join; reviewed claims stay on
   * the detail read. Audited as one read.
   */
  @Transactional(noRollbackFor = ForbiddenException.class)
  public EnrollmentPage listEnrollments(
      ServiceAccountPrincipal caller, String state, int limit, String cursor) {
    Decision decision =
        require(caller, Action.ENROLLMENT_READ, "enrollment", "list");
    String wanted = state == null || state.isBlank() ? "all" : state.strip().toLowerCase();
    String filter =
        switch (wanted) {
          case "all" -> "";
          case "pending" -> " AND e.state = 'PENDING'";
          case "in_review" -> " AND e.state = 'IN_REVIEW'";
          case "approved" -> " AND e.state = 'APPROVED'";
          case "rejected" -> " AND e.state = 'REJECTED'";
          default -> throw new EnrollmentInvalidException("unknown queue state");
        };
    int page = Math.min(Math.max(limit, 1), 200);
    KeysetCursor position = null;
    if (cursor != null && !cursor.isBlank()) {
      try {
        position = KeysetCursor.decode(cursor);
      } catch (IllegalArgumentException e) {
        throw new EnrollmentInvalidException("malformed list cursor");
      }
    }
    String keyset = position == null
        ? ""
        : " AND (e.created_at < ? OR (e.created_at = ? AND e.id < ?))";
    Object[] args;
    if (position == null) {
      args = new Object[] {caller.tenantId(), page + 1};
    } else {
      java.sql.Timestamp at = java.sql.Timestamp.from(position.createdAt());
      args = new Object[] {caller.tenantId(), at, at, position.id(), page + 1};
    }
    List<EnrollmentSummary> items =
        tenant.query(
            "SELECT e.id, e.subject_ref, e.vault_object_id, e.extraction_record_id,"
                + " e.bound_revision, e.state, e.created_by, e.decided_by, e.created_at,"
                + " r.approved_revision FROM enrollment e"
                + " LEFT JOIN extraction_record r ON r.id = e.extraction_record_id"
                + " WHERE e.tenant_id = ?" + filter + keyset
                + " ORDER BY e.created_at DESC, e.id DESC LIMIT ?",
            (rs, n) -> {
              String stateName = rs.getString("state");
              Integer head = rs.getObject("approved_revision", Integer.class);
              boolean eligible = "APPROVED".equals(stateName)
                  && head != null
                  && head == rs.getInt("bound_revision");
              String reason = "APPROVED".equals(stateName)
                  ? (eligible ? "CURRENT" : "STALE_SOURCE")
                  : "UNREVIEWED";
              return new EnrollmentSummary(
                  rs.getObject("id", UUID.class),
                  rs.getObject("subject_ref", UUID.class),
                  rs.getObject("vault_object_id", UUID.class),
                  rs.getObject("extraction_record_id", UUID.class),
                  rs.getInt("bound_revision"),
                  EnrollmentState.from(stateName),
                  rs.getString("created_by"),
                  rs.getString("decided_by"),
                  eligible,
                  reason,
                  rs.getTimestamp("created_at").toInstant().toString());
            },
            args);
    String next = null;
    List<EnrollmentSummary> shown = items;
    if (items.size() > page) {
      shown = items.subList(0, page);
      EnrollmentSummary last = shown.get(shown.size() - 1);
      next = KeysetCursor.encode(last.createdAt(), last.enrollmentId().toString());
    }
    audit.record(
        caller,
        Action.ENROLLMENT_READ,
        ResourceRef.tenantScoped("enrollment", "list", caller.tenantId()),
        decision,
        "",
        Map.of("state", wanted, "count", String.valueOf(shown.size())));
    return new EnrollmentPage(List.copyOf(shown), next);
  }

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
    String thumbprint =
        dev.sovra.crypto.P256.thumbprint(
            holderKey.getW().getAffineX(), holderKey.getW().getAffineY());
    tenant.update(
        "INSERT INTO enrollment (id, tenant_id, subject_ref, vault_object_id,"
            + " extraction_record_id, bound_revision, holder_jwk, holder_thumbprint, state,"
            + " created_by_account, created_by)"
            + " VALUES (?, ?, ?, ?, ?, ?, ?::jsonb, ?, 'PENDING', ?, ?)",
        enrollmentId,
        caller.tenantId(),
        subjectRef,
        vaultObjectId,
        extractionRecordId,
        record.approvedRevision(),
        writeJson(holderJwk),
        thumbprint,
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
    String activatedThumbprint = null;
    if (approve) {
      ECPublicKey holderKey = holderKey(readJwk(row.holderJwk));
      verifyBinding(holderKey, bindingProof, enrollmentId, revision);
      proofOk = true;
      activatedThumbprint =
          dev.sovra.crypto.P256.thumbprint(
              holderKey.getW().getAffineX(), holderKey.getW().getAffineY());
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
    if (approve) {
      // Approval activates the case key in the custody registry
      // (SOV-020): the key gains issuance authority here, and only
      // here. Re-review keeps the live key — a recovered enrollment
      // never falls back to its compromised original — and a key
      // already serving another enrollment conflicts instead of
      // aliasing.
      Integer live =
          tenant.queryForObject(
              "SELECT COUNT(*) FROM holder_key WHERE enrollment_id = ? AND status = ?",
              Integer.class,
              enrollmentId,
              dev.sovra.custody.HolderKeyStatus.ACTIVE.name());
      if (live == null || live == 0) {
        try {
          tenant.update(
              "INSERT INTO holder_key (tenant_id, enrollment_id, thumbprint, jwk, created_by)"
                  + " VALUES (?, ?, ?, ?::jsonb, ?)",
              caller.tenantId(),
              enrollmentId,
              activatedThumbprint,
              row.holderJwk,
              caller.name());
        } catch (org.springframework.dao.DuplicateKeyException e) {
          throw new EnrollmentConflictException("holder key is already registered");
        }
      }
    }
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
   * Issuance authorization (FR-37/39, SOV-020): returns the reviewed
   * claims only while the enrollment is APPROVED on the current
   * head AND the issuance holder key equals the enrollment's
   * ACTIVE registry key. Compromised keys lose issuance authority
   * at report time, even before recovery completes.
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
    List<String> active =
        tenant.query(
            "SELECT thumbprint FROM holder_key WHERE enrollment_id = ? AND status = ?",
            (rs, n) -> rs.getString(1),
            enrollmentId,
            dev.sovra.custody.HolderKeyStatus.ACTIVE.name());
    if (active.isEmpty()) {
      throw new EnrollmentConflictException("holder key is not active");
    }
    ECPublicKey offered;
    try {
      offered = HolderProofs.parseP256Key(holderJwk);
    } catch (HolderProofException e) {
      throw new EnrollmentInvalidException("issuance holder key is malformed");
    }
    String actual =
        dev.sovra.crypto.P256.thumbprint(
            offered.getW().getAffineX(), offered.getW().getAffineY());
    if (!java.security.MessageDigest.isEqual(
        active.get(0).getBytes(java.nio.charset.StandardCharsets.UTF_8),
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
