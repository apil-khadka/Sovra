package dev.sovra.custody;

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
import dev.sovra.crypto.P256;
import dev.sovra.enrollment.EnrollmentService;
import dev.sovra.issuance.IssuanceService;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Holder key custody and recovery (SOV-020, OD-09). Reports flip a
 * key to COMPROMISED and revoke its credentials immediately;
 * recovery activates a fresh proven key once the live enrollment
 * still qualifies. Only public key material is ever stored — the
 * SQL CHECK rejects private JWK fields, and registration reads
 * the case key server-side instead of trusting caller bytes.
 */
@Service
public class HolderCustodyService {

  static final String RECOVERY_LABEL = "holder-recovery";

  private static final Set<String> REASONS = Set.of("loss", "theft", "compromise");

  private final AuthorizationService authz;
  private final AuditService audit;
  private final EnrollmentService enrollment;
  private final IssuanceService issuance;
  private final JdbcTemplate tenant;
  private final ObjectMapper mapper;

  public HolderCustodyService(
      AuthorizationService authz,
      AuditService audit,
      EnrollmentService enrollment,
      IssuanceService issuance,
      JdbcTemplate tenantJdbcTemplate,
      ObjectMapper mapper) {
    this.authz = authz;
    this.audit = audit;
    this.enrollment = enrollment;
    this.issuance = issuance;
    this.tenant = tenantJdbcTemplate;
    this.mapper = mapper;
  }

  public record Reported(UUID keyId, UUID recoveryId, String thumbprint, int revokedCredentials) {}

  public record Recovered(UUID recoveryId, String newThumbprint) {}

  public record RecoveryView(
      UUID recoveryId, String reason, RecoveryState state, String newThumbprint) {}

  public record DeviceReported(
      UUID deviceId, String status, List<Reported> cases, int revokedCredentials) {}

  public record ReissuePlanItem(
      UUID credentialId,
      String issuerId,
      String vct,
      String idempotencyKey,
      boolean reissuable,
      String reason) {}

  public record ReissuePlan(
      UUID recoveryId,
      boolean enrollmentEligible,
      String eligibilityReason,
      List<ReissuePlanItem> items) {}

  public record ReissuedCredential(UUID oldCredentialId, UUID newCredentialId) {}

  public record Reissued(UUID recoveryId, List<ReissuedCredential> credentials) {}

  public record KeyView(
      UUID keyId,
      UUID enrollmentId,
      String thumbprint,
      HolderKeyStatus status,
      String createdBy,
      List<RecoveryView> recoveries) {}

  @Transactional(noRollbackFor = ForbiddenException.class)
  public Reported report(
      ServiceAccountPrincipal caller, String thumbprint, String reason) {
    Decision decision =
        require(caller, Action.HOLDER_REPORT, "holder-key", thumbprint == null ? "" : thumbprint);
    if (thumbprint == null || thumbprint.isBlank()) {
      throw new HolderCustodyInvalidException("thumbprint is required");
    }
    if (!REASONS.contains(reason)) {
      throw new HolderCustodyInvalidException("reason must be loss, theft, or compromise");
    }
    KeyRow key = keyByThumbprint(thumbprint.strip());
    if (key.status != HolderKeyStatus.ACTIVE) {
      throw new HolderCustodyConflictException("holder key is already reported");
    }
    return openRecoveryCase(caller, decision, key, reason);
  }

  /**
   * Device theft/loss report (PROD-015). The report names the device;
   * every live key bound to it gets its own recovery case and loses
   * presentation authority at once. One audit entry per key plus one
   * for the device keeps the trail traversable both ways.
   */
  @Transactional(noRollbackFor = ForbiddenException.class)
  public DeviceReported reportDevice(
      ServiceAccountPrincipal caller, UUID deviceId, String reason) {
    Decision decision =
        require(caller, Action.HOLDER_REPORT, "holder-device", deviceId.toString());
    if (!REASONS.contains(reason)) {
      throw new HolderCustodyInvalidException("reason must be loss, theft, or compromise");
    }
    DeviceRow device = deviceRow(deviceId);
    if (!"ACTIVE".equals(device.status)) {
      throw new HolderCustodyConflictException("holder device is already reported");
    }
    String status =
        switch (reason) {
          case "loss" -> "LOST";
          case "theft" -> "STOLEN";
          default -> "COMPROMISED";
        };
    tenant.update(
        "UPDATE holder_device SET status = ?, reported_by = ?, reported_at = now() WHERE id = ?",
        status, caller.name(), deviceId);
    List<KeyRow> keys =
        tenant.query(
            "SELECT id, enrollment_id, thumbprint, status, jwk, created_by FROM holder_key"
                + " WHERE device_id = ? AND status = ?",
            this::mapKey,
            deviceId,
            HolderKeyStatus.ACTIVE.name());
    List<Reported> cases = new ArrayList<>();
    int revoked = 0;
    for (KeyRow key : keys) {
      Reported reported = openRecoveryCase(caller, decision, key, reason);
      cases.add(reported);
      revoked += reported.revokedCredentials();
    }
    audit.record(
        caller,
        Action.HOLDER_REPORT,
        ResourceRef.tenantScoped("holder-device", deviceId.toString(), caller.tenantId()),
        decision,
        "",
        Map.of(
            "reason", reason,
            "keys", String.valueOf(cases.size()),
            "revoked", String.valueOf(revoked)));
    return new DeviceReported(deviceId, status, cases, revoked);
  }

  /**
   * Recovery-scoped reissue plan (PROD-015): the exact credentials
   * the report killed, with the deterministic idempotency key each
   * reissue must use. Only linked REVOKED rows are reissuable —
   * earlier independent revocations stay dead.
   */
  @Transactional(noRollbackFor = ForbiddenException.class)
  public ReissuePlan reissuePlan(ServiceAccountPrincipal caller, UUID recoveryId) {
    Decision decision =
        require(caller, Action.HOLDER_READ, "holder-recovery", recoveryId.toString());
    RecoveryRow recovery = recoveryRow(recoveryId);
    if (recovery.state != RecoveryState.RECOVERED) {
      throw new HolderCustodyConflictException("recovery is not complete");
    }
    EnrollmentService.EligibilityView eligible =
        enrollment.eligibilityFor(caller, recovery.enrollmentId);
    List<ReissuePlanItem> items = reissueTargets(recoveryId);
    audit.record(
        caller,
        Action.HOLDER_READ,
        ResourceRef.tenantScoped("holder-recovery", recoveryId.toString(), caller.tenantId()),
        decision,
        "",
        Map.of("items", String.valueOf(items.size())));
    return new ReissuePlan(
        recoveryId, eligible.eligible(), eligible.reason(), items);
  }

  /**
   * Recovery-scoped reissuance (PROD-015). Separation of duties is
   * structural: TRUST_ADMIN completes the recovery, ISSUER_OPS
   * reissues — neither role holds the other's step, and reissue is
   * impossible before recovery. Every reissued credential binds the
   * replacement key, carries the enrollment's reviewed claims, earns
   * its validity window from the recovery event against the live
   * eligibility proof, and chains to the revoked id it replaces.
   * All-or-nothing: a bad proof anywhere rolls the whole batch back.
   */
  @Transactional(noRollbackFor = ForbiddenException.class)
  public Reissued reissue(
      ServiceAccountPrincipal caller, UUID recoveryId, Map<String, String> proofs) {
    Decision decision =
        require(caller, Action.ISSUE_CREDENTIAL, "holder-recovery", recoveryId.toString());
    RecoveryRow recovery = recoveryRow(recoveryId);
    if (recovery.state != RecoveryState.RECOVERED || recovery.newKeyId == null) {
      throw new HolderCustodyConflictException("recovery is not complete");
    }
    if (recovery.recoveredAt == null) {
      throw new IllegalStateException("recovery completion is unreadable");
    }
    KeyRow fresh = keyRow(recovery.newKeyId);
    if (fresh.status != HolderKeyStatus.ACTIVE) {
      throw new HolderCustodyConflictException("replacement key is no longer active");
    }
    // Re-proof of the live case at reissue time: the enrollment must
    // still qualify AND the replacement key must be its live binding.
    // Reissuance replaces like-for-like — the adult-status claim the
    // evidence carries — and only when the live case still supports
    // it; the reviewed map itself carries raw PII that issuance
    // would (correctly) refuse as unallowlisted.
    Map<String, String> reviewed =
        enrollment.issuanceClaims(caller, recovery.enrollmentId, fresh.jwk);
    if (!"true".equals(reviewed.get("adultOver18"))) {
      throw new HolderCustodyConflictException("enrollment no longer authorizes adult status");
    }
    Map<String, Object> claims = Map.of("adultOver18", Boolean.TRUE);
    List<ReissuePlanItem> targets =
        reissueTargets(recoveryId).stream().filter(ReissuePlanItem::reissuable).toList();
    if (proofs == null) {
      proofs = Map.of();
    }
    for (ReissuePlanItem target : targets) {
      String proof = proofs.get(target.credentialId().toString());
      if (proof == null || proof.isBlank()) {
        throw new HolderCustodyInvalidException(
            "issuance proof is missing for credential " + target.credentialId());
      }
    }
    // Validity anchors to the recovery event, not to this call:
    // identical reissue retries replay byte-for-byte instead of
    // conflicting on a fresh timestamp.
    Instant expiresAt = recovery.recoveredAt.plus(java.time.Duration.ofDays(365));
    List<ReissuedCredential> done = new ArrayList<>();
    for (ReissuePlanItem target : targets) {
      String response =
          issuance.issue(
              caller,
              new IssuanceService.IssueRequest(
                  target.issuerId(),
                  target.vct(),
                  fresh.jwk,
                  proofs.get(target.credentialId().toString()),
                  claims,
                  expiresAt,
                  recovery.enrollmentId),
              target.idempotencyKey());
      UUID newId = parseCredentialId(response);
      tenant.update(
          "UPDATE credential_artifact SET supersedes = ? WHERE id = ?", target.credentialId(),
          newId);
      done.add(new ReissuedCredential(target.credentialId(), newId));
    }
    audit.record(
        caller,
        Action.ISSUE_CREDENTIAL,
        ResourceRef.tenantScoped("holder-recovery", recoveryId.toString(), caller.tenantId()),
        decision,
        "",
        Map.of("reissued", String.valueOf(done.size())));
    return new Reissued(recoveryId, done);
  }

  private Reported openRecoveryCase(
      ServiceAccountPrincipal caller, Decision decision, KeyRow key, String reason) {
    tenant.update(
        "UPDATE holder_key SET status = ? WHERE id = ?",
        HolderKeyStatus.COMPROMISED.name(), key.id);
    UUID recoveryId = UUID.randomUUID();
    try {
      tenant.update(
          "INSERT INTO holder_recovery (id, tenant_id, holder_key_id, enrollment_id, reason,"
              + " reported_by) VALUES (?, ?, ?, ?, ?, ?)",
          recoveryId, caller.tenantId(), key.id, key.enrollmentId, reason, caller.name());
    } catch (DuplicateKeyException e) {
      // A concurrent report won the open-case index; the key flip
      // above converges with it.
      throw new HolderCustodyConflictException("holder key is already reported");
    }
    // Revocation lands at report time, before recovery completes,
    // so a stolen key loses presentation authority immediately. The
    // flipped rows link to this recovery, scoping later reissuance.
    int revoked = issuance.revokeByHolder(caller, key.thumbprint, recoveryId);
    audit.record(
        caller,
        Action.HOLDER_REPORT,
        ResourceRef.tenantScoped("holder-key", key.id.toString(), caller.tenantId()),
        decision,
        "",
        Map.of("reason", reason, "revoked", String.valueOf(revoked)));
    return new Reported(key.id, recoveryId, key.thumbprint, revoked);
  }

  static String reissueKey(UUID recoveryId, UUID credentialId) {
    return "recovery-" + recoveryId + "-" + credentialId;
  }

  private List<ReissuePlanItem> reissueTargets(UUID recoveryId) {
    return tenant.query(
        "SELECT id, issuer_id, vct, status FROM credential_artifact"
            + " WHERE revoked_by_recovery = ? ORDER BY issued_at",
        (rs, n) -> {
          UUID credentialId = rs.getObject("id", UUID.class);
          boolean reissuable = "REVOKED".equals(rs.getString("status"));
          return new ReissuePlanItem(
              credentialId,
              rs.getString("issuer_id"),
              rs.getString("vct"),
              reissueKey(recoveryId, credentialId),
              reissuable,
              reissuable ? "" : "credential is not revoked");
        },
        recoveryId);
  }

  private UUID parseCredentialId(String response) {
    try {
      return UUID.fromString(mapper.readTree(response).get("credentialId").asString());
    } catch (Exception e) {
      throw new IllegalStateException("issuance response is unreadable", e);
    }
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public Recovered recover(
      ServiceAccountPrincipal caller,
      UUID recoveryId,
      JsonNode newHolderJwk,
      String newKeyProof) {
    return recover(caller, recoveryId, newHolderJwk, newKeyProof, null);
  }

  /**
   * Recovery with device binding (PROD-015). A named replacement
   * device is minted ACTIVE and the fresh key binds to it; a blank
   * label keeps key-level recovery without device facts (server-side
   * rotation), leaving device_id null like pre-device keys.
   */
  @Transactional(noRollbackFor = ForbiddenException.class)
  public Recovered recover(
      ServiceAccountPrincipal caller,
      UUID recoveryId,
      JsonNode newHolderJwk,
      String newKeyProof,
      String deviceLabel) {
    Decision decision =
        require(caller, Action.HOLDER_RECOVER, "holder-recovery", recoveryId.toString());
    if (newHolderJwk == null) {
      throw new HolderCustodyInvalidException("replacement holder key is required");
    }
    ECPublicKey fresh;
    try {
      fresh = HolderProofs.parseP256Key(newHolderJwk);
    } catch (HolderProofException e) {
      throw new HolderCustodyInvalidException("replacement holder key is malformed");
    }
    RecoveryRow recovery = recoveryRow(recoveryId);
    if (recovery.state != RecoveryState.REPORTED) {
      throw new HolderCustodyConflictException("recovery is already complete");
    }
    // Re-proof of the live case, not of the lost key: stale or
    // rejected enrollments terminate recovery (FR-39, SEC-39).
    EnrollmentService.EligibilityView eligible =
        enrollment.eligibilityFor(caller, recovery.enrollmentId);
    if (!eligible.eligible()) {
      throw new HolderCustodyConflictException(
          "enrollment is " + eligible.reason().toLowerCase());
    }
    String newThumbprint =
        P256.thumbprint(fresh.getW().getAffineX(), fresh.getW().getAffineY());
    if (newKeyProof == null || newKeyProof.isBlank()) {
      throw new HolderCustodyInvalidException("replacement key proof is required");
    }
    try {
      HolderProofs.verifyEs256(
          fresh, newKeyProof, RECOVERY_LABEL + "\n" + recoveryId + "\n" + newThumbprint, mapper);
    } catch (HolderProofException e) {
      throw new HolderCustodyInvalidException("replacement key proof is invalid");
    }
    UUID deviceId = null;
    if (deviceLabel != null && !deviceLabel.isBlank()) {
      String label = deviceLabel.strip();
      if (label.length() > 64) {
        throw new HolderCustodyInvalidException("device label is too long");
      }
      deviceId = UUID.randomUUID();
      try {
        tenant.update(
            "INSERT INTO holder_device (id, tenant_id, enrollment_id, label)"
                + " VALUES (?, ?, ?, ?)",
            deviceId, caller.tenantId(), recovery.enrollmentId, label);
      } catch (DuplicateKeyException e) {
        throw new HolderCustodyConflictException("device label is already registered");
      }
    }
    UUID newKeyId = UUID.randomUUID();
    try {
      tenant.update(
          "INSERT INTO holder_key (id, tenant_id, enrollment_id, thumbprint, jwk, supersedes,"
              + " device_id, created_by) VALUES (?, ?, ?, ?, ?::jsonb, ?, ?, ?)",
          newKeyId,
          caller.tenantId(),
          recovery.enrollmentId,
          newThumbprint,
          writeJson(newHolderJwk),
          recovery.holderKeyId,
          deviceId,
          caller.name());
    } catch (DuplicateKeyException e) {
      throw new HolderCustodyConflictException("replacement key is already registered");
    }
    tenant.update(
        "UPDATE holder_recovery SET state = ?, new_key_id = ?, recovered_by = ?,"
            + " recovered_at = now() WHERE id = ?",
        RecoveryState.RECOVERED.name(), newKeyId, caller.name(), recoveryId);
    audit.record(
        caller,
        Action.HOLDER_RECOVER,
        ResourceRef.tenantScoped("holder-recovery", recoveryId.toString(), caller.tenantId()),
        decision,
        "",
        Map.of("replaced", recovery.holderKeyId.toString()));
    return new Recovered(recoveryId, newThumbprint);
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public KeyView read(ServiceAccountPrincipal caller, UUID keyId) {
    Decision decision =
        require(caller, Action.HOLDER_READ, "holder-key", keyId.toString());
    KeyRow key = keyRow(keyId);
    List<RecoveryView> recoveries =
        tenant.query(
            "SELECT r.id, r.reason, r.state, k.thumbprint AS new_thumbprint"
                + " FROM holder_recovery r LEFT JOIN holder_key k ON k.id = r.new_key_id"
                + " WHERE r.holder_key_id = ? ORDER BY r.created_at",
            (rs, n) -> new RecoveryView(
                rs.getObject("id", UUID.class),
                rs.getString("reason"),
                RecoveryState.from(rs.getString("state")),
                rs.getString("new_thumbprint")),
            keyId);
    audit.record(
        caller,
        Action.HOLDER_READ,
        ResourceRef.tenantScoped("holder-key", keyId.toString(), caller.tenantId()),
        decision,
        "",
        Map.of("status", key.status.name()));
    return new KeyView(
        key.id, key.enrollmentId, key.thumbprint, key.status, key.createdBy, recoveries);
  }

  private String writeJson(JsonNode node) {
    try {
      return mapper.writeValueAsString(node);
    } catch (Exception e) {
      throw new HolderCustodyInvalidException("replacement holder key is malformed");
    }
  }

  private record KeyRow(
      UUID id,
      UUID enrollmentId,
      String thumbprint,
      HolderKeyStatus status,
      JsonNode jwk,
      String createdBy) {}

  private KeyRow mapKey(java.sql.ResultSet rs, int n) throws java.sql.SQLException {
    JsonNode jwk;
    try {
      jwk = mapper.readTree(rs.getString("jwk"));
    } catch (Exception e) {
      throw new IllegalStateException("stored holder key is unreadable", e);
    }
    return new KeyRow(
        rs.getObject("id", UUID.class),
        rs.getObject("enrollment_id", UUID.class),
        rs.getString("thumbprint"),
        HolderKeyStatus.from(rs.getString("status")),
        jwk,
        rs.getString("created_by"));
  }

  private KeyRow keyRow(UUID keyId) {
    List<KeyRow> rows =
        tenant.query(
            "SELECT id, enrollment_id, thumbprint, status, jwk, created_by FROM holder_key"
                + " WHERE id = ?",
            this::mapKey,
            keyId);
    if (rows.isEmpty()) {
      throw new HolderCustodyNotFoundException();
    }
    return rows.get(0);
  }

  private KeyRow keyByThumbprint(String thumbprint) {
    List<KeyRow> rows =
        tenant.query(
            "SELECT id, enrollment_id, thumbprint, status, jwk, created_by FROM holder_key"
                + " WHERE thumbprint = ?",
            this::mapKey,
            thumbprint);
    if (rows.isEmpty()) {
      throw new HolderCustodyNotFoundException();
    }
    return rows.get(0);
  }

  private record DeviceRow(UUID id, UUID enrollmentId, String label, String status) {}

  private DeviceRow deviceRow(UUID deviceId) {
    List<DeviceRow> rows =
        tenant.query(
            "SELECT id, enrollment_id, label, status FROM holder_device WHERE id = ?",
            (rs, n) -> new DeviceRow(
                rs.getObject("id", UUID.class),
                rs.getObject("enrollment_id", UUID.class),
                rs.getString("label"),
                rs.getString("status")),
            deviceId);
    if (rows.isEmpty()) {
      throw new HolderCustodyNotFoundException();
    }
    return rows.get(0);
  }

  private record RecoveryRow(
      UUID id,
      UUID holderKeyId,
      UUID enrollmentId,
      RecoveryState state,
      UUID newKeyId,
      Instant recoveredAt) {}

  private RecoveryRow recoveryRow(UUID recoveryId) {
    List<RecoveryRow> rows =
        tenant.query(
            "SELECT id, holder_key_id, enrollment_id, state, new_key_id, recovered_at"
                + " FROM holder_recovery WHERE id = ?",
            (rs, n) -> new RecoveryRow(
                rs.getObject("id", UUID.class),
                rs.getObject("holder_key_id", UUID.class),
                rs.getObject("enrollment_id", UUID.class),
                RecoveryState.from(rs.getString("state")),
                rs.getObject("new_key_id", UUID.class),
                rs.getObject("recovered_at", java.sql.Timestamp.class) == null
                    ? null
                    : rs.getObject("recovered_at", java.sql.Timestamp.class).toInstant()),
            recoveryId);
    if (rows.isEmpty()) {
      throw new HolderCustodyNotFoundException();
    }
    return rows.get(0);
  }

  private Decision require(
      ServiceAccountPrincipal caller, Action action, String type, String id) {
    return AuditedAuthorizer.require(
        authz, audit, caller, action, ResourceRef.tenantScoped(type, id, caller.tenantId()));
  }
}
