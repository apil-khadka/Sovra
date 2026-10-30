package dev.sovra.bff;

import dev.sovra.audit.AuditService;
import dev.sovra.audit.AuditedAuthorizer;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ResourceRef;
import dev.sovra.enrollment.EnrollmentNotFoundException;
import dev.sovra.enrollment.EnrollmentState;
import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

/**
 * Holder self-reads (SOV-024): cases, disclosures, credentials,
 * and recovery for exactly the thumbprint the session unlocked.
 * Every query filters by tenant and proven thumbprint; detail
 * reads 404 unless the row belongs to that key, so one holder
 * can neither list nor guess another's history. Audited as
 * holder self-reads.
 */
@Service
public class HolderDeskService {

  private final AuthorizationService authz;
  private final AuditService audit;
  private final JdbcTemplate tenant;
  private final ObjectMapper mapper;

  public HolderDeskService(
      AuthorizationService authz,
      AuditService audit,
      JdbcTemplate tenantJdbcTemplate,
      ObjectMapper mapper) {
    this.authz = authz;
    this.audit = audit;
    this.tenant = tenantJdbcTemplate;
    this.mapper = mapper;
  }

  public record HolderCase(
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

  public record CaseReview(int revision, String decision, boolean bindingProofOk, String reviewer) {}

  public record CaseRevision(
      int revNo,
      Map<String, String> observed,
      Map<String, String> normalized,
      BigDecimal confidence,
      Integer supersedes,
      String createdBy) {}

  public record CaseDetail(
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
      List<CaseReview> reviews,
      Integer approvedRevision,
      List<CaseRevision> revisions) {}

  public record Disclosure(
      UUID requestId,
      String rpId,
      String audience,
      String purpose,
      UUID credentialId,
      Map<String, Object> claims,
      String state,
      String createdAt,
      String expiresAt,
      String decidedAt,
      String verificationOutcome,
      long trustSnapshot) {}

  public record HolderCredential(
      UUID credentialId,
      String issuerId,
      String vct,
      String keyRef,
      String issuedAt,
      String expiresAt,
      String status,
      long trustSnapshot) {}

  public record RecoveryAttempt(
      UUID recoveryId, String reason, String state, String newThumbprint, String createdAt) {}

  public record RecoveryStatus(
      UUID keyId, String thumbprint, String status, List<RecoveryAttempt> recoveries) {}

  @Transactional(noRollbackFor = ForbiddenException.class)
  public List<HolderCase> cases(ServiceAccountPrincipal caller, String thumbprint) {
    Decision decision = require(caller, "holder-case", "list");
    List<HolderCase> items =
        tenant.query(
            "SELECT e.id, e.subject_ref, e.vault_object_id, e.extraction_record_id,"
                + " e.bound_revision, e.state, e.created_by, e.decided_by, e.created_at,"
                + " r.approved_revision FROM enrollment e"
                + " LEFT JOIN extraction_record r ON r.id = e.extraction_record_id"
                + " WHERE e.tenant_id = ? AND e.holder_thumbprint = ?"
                + " ORDER BY e.created_at DESC, e.id DESC LIMIT 50",
            (rs, n) -> {
              String stateName = rs.getString("state");
              Integer head = rs.getObject("approved_revision", Integer.class);
              boolean eligible = "APPROVED".equals(stateName)
                  && head != null
                  && head == rs.getInt("bound_revision");
              String reason = "APPROVED".equals(stateName)
                  ? (eligible ? "CURRENT" : "STALE_SOURCE")
                  : "UNREVIEWED";
              return new HolderCase(
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
            caller.tenantId(),
            thumbprint);
    audit.record(
        caller,
        Action.HOLDER_READ_SELF,
        ResourceRef.tenantScoped("holder-case", "list", caller.tenantId()),
        decision,
        "",
        Map.of("count", String.valueOf(items.size())));
    return items;
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public CaseDetail caseDetail(
      ServiceAccountPrincipal caller, String thumbprint, UUID enrollmentId) {
    Decision decision = require(caller, "holder-case", enrollmentId.toString());
    List<HolderCase> rows = casesOwned(caller.tenantId(), thumbprint, enrollmentId);
    if (rows.isEmpty()) {
      throw new EnrollmentNotFoundException();
    }
    HolderCase owned = rows.get(0);
    List<CaseReview> reviews =
        tenant.query(
            "SELECT revision, decision, binding_proof_ok, reviewer FROM enrollment_review"
                + " WHERE enrollment_id = ? ORDER BY created_at, revision",
            (rs, n) -> new CaseReview(
                rs.getInt("revision"),
                rs.getString("decision"),
                rs.getBoolean("binding_proof_ok"),
                rs.getString("reviewer")),
            enrollmentId);
    Integer approved =
        tenant.query(
            "SELECT approved_revision FROM extraction_record WHERE id = ?",
            (rs, n) -> rs.getObject("approved_revision", Integer.class),
            owned.extractionRecordId()).stream().findFirst().orElse(null);
    List<CaseRevision> revisions =
        tenant.query(
            "SELECT rev_no, observed, normalized, confidence, supersedes, created_by"
                + " FROM extraction_revision WHERE record_id = ? ORDER BY rev_no",
            (rs, n) -> new CaseRevision(
                rs.getInt("rev_no"),
                stringMap(rs.getString("observed")),
                stringMap(rs.getString("normalized")),
                rs.getBigDecimal("confidence"),
                rs.getObject("supersedes", Integer.class),
                rs.getString("created_by")),
            owned.extractionRecordId());
    audit.record(
        caller,
        Action.HOLDER_READ_SELF,
        ResourceRef.tenantScoped("holder-case", enrollmentId.toString(), caller.tenantId()),
        decision,
        "",
        Map.of("state", owned.state().name()));
    return new CaseDetail(
        owned.enrollmentId(),
        owned.subjectRef(),
        owned.vaultObjectId(),
        owned.extractionRecordId(),
        owned.boundRevision(),
        owned.state(),
        owned.createdBy(),
        owned.decidedBy(),
        owned.eligible(),
        owned.eligibilityReason(),
        reviews,
        approved,
        revisions);
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public List<Disclosure> disclosures(ServiceAccountPrincipal caller, String thumbprint) {
    Decision decision = require(caller, "holder-disclosure", "list");
    List<Disclosure> items =
        tenant.query(
            "SELECT p.id, p.rp_id, p.audience, p.purpose, p.credential_id, p.claims, p.state,"
                + " p.created_at, p.expires_at, p.decided_at, p.trust_snapshot_version,"
                + " (SELECT d.outcome FROM verification_decision d"
                + " WHERE d.request_id = p.id ORDER BY d.decided_at DESC LIMIT 1) AS outcome"
                + " FROM proof_request p WHERE p.tenant_id = ? AND p.holder_thumbprint = ?"
                + " ORDER BY p.created_at DESC, p.id DESC LIMIT 50",
            (rs, n) -> new Disclosure(
                rs.getObject("id", UUID.class),
                rs.getString("rp_id"),
                rs.getString("audience"),
                rs.getString("purpose"),
                rs.getObject("credential_id", UUID.class),
                objectMap(rs.getString("claims")),
                rs.getString("state"),
                rs.getTimestamp("created_at").toInstant().toString(),
                rs.getTimestamp("expires_at").toInstant().toString(),
                rs.getTimestamp("decided_at") == null
                    ? null
                    : rs.getTimestamp("decided_at").toInstant().toString(),
                rs.getString("outcome"),
                rs.getLong("trust_snapshot_version")),
            caller.tenantId(),
            thumbprint);
    audit.record(
        caller,
        Action.HOLDER_READ_SELF,
        ResourceRef.tenantScoped("holder-disclosure", "list", caller.tenantId()),
        decision,
        "",
        Map.of("count", String.valueOf(items.size())));
    return items;
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public List<HolderCredential> credentials(ServiceAccountPrincipal caller, String thumbprint) {
    Decision decision = require(caller, "holder-credential", "list");
    List<HolderCredential> items =
        tenant.query(
            "SELECT id, issuer_id, vct, key_ref, issued_at, expires_at, status,"
                + " trust_snapshot_version FROM credential_artifact"
                + " WHERE tenant_id = ? AND holder_thumbprint = ?"
                + " ORDER BY issued_at DESC, id DESC LIMIT 50",
            (rs, n) -> new HolderCredential(
                rs.getObject("id", UUID.class),
                rs.getString("issuer_id"),
                rs.getString("vct"),
                rs.getString("key_ref"),
                rs.getTimestamp("issued_at").toInstant().toString(),
                rs.getTimestamp("expires_at").toInstant().toString(),
                rs.getString("status"),
                rs.getLong("trust_snapshot_version")),
            caller.tenantId(),
            thumbprint);
    audit.record(
        caller,
        Action.HOLDER_READ_SELF,
        ResourceRef.tenantScoped("holder-credential", "list", caller.tenantId()),
        decision,
        "",
        Map.of("count", String.valueOf(items.size())));
    return items;
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public RecoveryStatus recovery(ServiceAccountPrincipal caller, String thumbprint) {
    Decision decision = require(caller, "holder-recovery", "read");
    List<RecoveryStatus> keys =
        tenant.query(
            "SELECT id, thumbprint, status FROM holder_key"
                + " WHERE tenant_id = ? AND thumbprint = ?",
            (rs, n) -> new RecoveryStatus(
                rs.getObject("id", UUID.class),
                rs.getString("thumbprint"),
                rs.getString("status"),
                List.of()),
            caller.tenantId(),
            thumbprint);
    audit.record(
        caller,
        Action.HOLDER_READ_SELF,
        ResourceRef.tenantScoped("holder-recovery", "read", caller.tenantId()),
        decision,
        "",
        Map.of("registered", String.valueOf(!keys.isEmpty())));
    if (keys.isEmpty()) {
      return new RecoveryStatus(null, thumbprint, "UNREGISTERED", List.of());
    }
    RecoveryStatus key = keys.get(0);
    List<RecoveryAttempt> attempts =
        tenant.query(
            "SELECT r.id, r.reason, r.state, k.thumbprint AS new_thumbprint, r.created_at"
                + " FROM holder_recovery r LEFT JOIN holder_key k ON k.id = r.new_key_id"
                + " WHERE r.holder_key_id = ? ORDER BY r.created_at",
            (rs, n) -> new RecoveryAttempt(
                rs.getObject("id", UUID.class),
                rs.getString("reason"),
                rs.getString("state"),
                rs.getString("new_thumbprint"),
                rs.getTimestamp("created_at").toInstant().toString()),
            key.keyId());
    return new RecoveryStatus(key.keyId(), key.thumbprint(), key.status(), attempts);
  }

  private List<HolderCase> casesOwned(UUID tenantId, String thumbprint, UUID enrollmentId) {
    return tenant.query(
        "SELECT e.id, e.subject_ref, e.vault_object_id, e.extraction_record_id,"
            + " e.bound_revision, e.state, e.created_by, e.decided_by, e.created_at,"
            + " r.approved_revision FROM enrollment e"
            + " LEFT JOIN extraction_record r ON r.id = e.extraction_record_id"
            + " WHERE e.tenant_id = ? AND e.holder_thumbprint = ? AND e.id = ?",
        (rs, n) -> {
          String stateName = rs.getString("state");
          Integer head = rs.getObject("approved_revision", Integer.class);
          boolean eligible = "APPROVED".equals(stateName)
              && head != null
              && head == rs.getInt("bound_revision");
          String reason = "APPROVED".equals(stateName)
              ? (eligible ? "CURRENT" : "STALE_SOURCE")
              : "UNREVIEWED";
          return new HolderCase(
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
        tenantId,
        thumbprint,
        enrollmentId);
  }

  private Map<String, String> stringMap(String json) {
    try {
      Map<String, String> out = new TreeMap<>();
      mapper.readTree(json).properties().forEach(e -> out.put(e.getKey(), e.getValue().asString()));
      return Map.copyOf(out);
    } catch (tools.jackson.core.JacksonException e) {
      throw new IllegalStateException("stored revision fields are not JSON", e);
    }
  }

  private Map<String, Object> objectMap(String json) {
    try {
      return mapper.readValue(json, Map.class);
    } catch (tools.jackson.core.JacksonException e) {
      throw new IllegalStateException("stored consent claims are not JSON", e);
    }
  }

  private Decision require(ServiceAccountPrincipal caller, String type, String id) {
    return AuditedAuthorizer.require(
        authz, audit, caller, Action.HOLDER_READ_SELF,
        ResourceRef.tenantScoped(type, id, caller.tenantId()));
  }
}
