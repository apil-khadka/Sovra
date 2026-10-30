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
    // so a stolen key loses presentation authority immediately.
    int revoked = issuance.revokeByHolder(caller, key.thumbprint);
    audit.record(
        caller,
        Action.HOLDER_REPORT,
        ResourceRef.tenantScoped("holder-key", key.id.toString(), caller.tenantId()),
        decision,
        "",
        Map.of("reason", reason, "revoked", String.valueOf(revoked)));
    return new Reported(key.id, recoveryId, key.thumbprint, revoked);
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public Recovered recover(
      ServiceAccountPrincipal caller,
      UUID recoveryId,
      JsonNode newHolderJwk,
      String newKeyProof) {
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
    UUID newKeyId = UUID.randomUUID();
    try {
      tenant.update(
          "INSERT INTO holder_key (id, tenant_id, enrollment_id, thumbprint, jwk, supersedes,"
              + " created_by) VALUES (?, ?, ?, ?, ?::jsonb, ?, ?)",
          newKeyId,
          caller.tenantId(),
          recovery.enrollmentId,
          newThumbprint,
          writeJson(newHolderJwk),
          recovery.holderKeyId,
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
      UUID id, UUID enrollmentId, String thumbprint, HolderKeyStatus status, String createdBy) {}

  private KeyRow keyRow(UUID keyId) {
    List<KeyRow> rows =
        tenant.query(
            "SELECT id, enrollment_id, thumbprint, status, created_by FROM holder_key"
                + " WHERE id = ?",
            (rs, n) -> new KeyRow(
                rs.getObject("id", UUID.class),
                rs.getObject("enrollment_id", UUID.class),
                rs.getString("thumbprint"),
                HolderKeyStatus.from(rs.getString("status")),
                rs.getString("created_by")),
            keyId);
    if (rows.isEmpty()) {
      throw new HolderCustodyNotFoundException();
    }
    return rows.get(0);
  }

  private KeyRow keyByThumbprint(String thumbprint) {
    List<KeyRow> rows =
        tenant.query(
            "SELECT id, enrollment_id, thumbprint, status, created_by FROM holder_key"
                + " WHERE thumbprint = ?",
            (rs, n) -> new KeyRow(
                rs.getObject("id", UUID.class),
                rs.getObject("enrollment_id", UUID.class),
                rs.getString("thumbprint"),
                HolderKeyStatus.from(rs.getString("status")),
                rs.getString("created_by")),
            thumbprint);
    if (rows.isEmpty()) {
      throw new HolderCustodyNotFoundException();
    }
    return rows.get(0);
  }

  private record RecoveryRow(
      UUID id, UUID holderKeyId, UUID enrollmentId, RecoveryState state) {}

  private RecoveryRow recoveryRow(UUID recoveryId) {
    List<RecoveryRow> rows =
        tenant.query(
            "SELECT id, holder_key_id, enrollment_id, state FROM holder_recovery WHERE id = ?",
            (rs, n) -> new RecoveryRow(
                rs.getObject("id", UUID.class),
                rs.getObject("holder_key_id", UUID.class),
                rs.getObject("enrollment_id", UUID.class),
                RecoveryState.from(rs.getString("state"))),
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
