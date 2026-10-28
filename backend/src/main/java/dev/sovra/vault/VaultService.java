package dev.sovra.vault;

import dev.sovra.audit.AuditService;
import dev.sovra.auth.HumanMembershipRepository;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.auth.ServiceAccountRepository;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.authz.ResourceRef;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Encrypted local vault (SOV-016). Per-object-version envelope AEAD:
 * a fresh random DEK per version seals content under identity-bound
 * AAD, and the DEK wraps under a versioned tenant KEK with wrap
 * context binding the authorized purposes. Unwrap requires a live,
 * exactly-matching grant plus current role authorization; KMS
 * outages and integrity failures release nothing and fall back to
 * nothing. DEKs and plaintext exist only as method locals for the
 * one authorized operation — zero cross-request cache entries.
 */
@Service
public class VaultService {

  static final int MAX_CONTENT_BYTES = 16777216 - 16;
  static final long MIN_GRANT_TTL_SECONDS = 60;
  static final long MAX_GRANT_TTL_SECONDS = 86400;

  /**
   * Quarantine marker purpose (SOV-017). Objects carrying it are
   * unscanned hostile input: the content endpoint refuses them even
   * under a live grant, and only {@link #readForQuarantine} opens
   * them, server-side, during promotion of a CLEAN verdict.
   */
  public static final String QUARANTINE_PURPOSE = "quarantine-scan";

  private static final Pattern NAME = Pattern.compile("^[a-z0-9-]{1,64}$");

  private final AuthorizationService authz;
  private final AuditService audit;
  private final ServiceAccountRepository accounts;
  private final HumanMembershipRepository humans;
  private final VaultKekProvider kek;
  private final JdbcTemplate tenant;
  private final Clock clock;

  public VaultService(
      AuthorizationService authz,
      AuditService audit,
      ServiceAccountRepository accounts,
      HumanMembershipRepository humans,
      VaultKekProvider kek,
      JdbcTemplate tenantJdbcTemplate,
      Clock clock) {
    this.authz = authz;
    this.audit = audit;
    this.accounts = accounts;
    this.humans = humans;
    this.kek = kek;
    this.tenant = tenantJdbcTemplate;
    this.clock = clock;
  }

  public record StoredVersion(UUID objectId, int version) {}

  public record VersionMetadata(
      int version,
      List<String> purposes,
      int kekVersion,
      String status,
      String contentSha256Hex,
      Instant createdAt) {}

  public record ObjectMetadata(
      UUID objectId, String issuerId, String displayName, List<VersionMetadata> versions) {}

  public record GrantView(
      UUID grantId,
      UUID objectId,
      int objectVersion,
      String principalType,
      UUID principalId,
      String purpose,
      String workload,
      boolean revoked,
      Instant expiresAt,
      Instant createdAt) {}

  public record ReadResult(byte[] content, int version, String contentSha256Hex) {}

  private record StoredRow(
      UUID objectId,
      int version,
      String issuerId,
      List<String> purposes,
      byte[] contentSha256,
      int kekVersion,
      byte[] wrappedDek,
      byte[] dekNonce,
      byte[] contentNonce,
      byte[] ciphertext,
      String status) {}

  private record GrantRow(
      UUID id,
      UUID objectId,
      int objectVersion,
      String principalType,
      UUID principalId,
      String purpose,
      String workload,
      boolean revoked,
      Instant expiresAt,
      Instant createdAt) {}

  @Transactional(noRollbackFor = {ForbiddenException.class, VaultAuthenticationException.class})
  public StoredVersion store(
      ServiceAccountPrincipal caller,
      String issuerId,
      String displayName,
      List<String> purposes,
      byte[] content,
      String expectedSha256Hex) {
    Decision decision = require(caller, Action.VAULT_STORE_OBJECT, "vault-object", "store");
    List<String> authorized = validatedPurposes(purposes);
    byte[] bytes = validatedContent(content, expectedSha256Hex);
    requireText(issuerId, "issuer id");
    UUID objectId = UUID.randomUUID();
    tenant.update(
        "INSERT INTO vault_object (id, tenant_id, issuer_id, display_name, created_by)"
            + " VALUES (?, ?, ?, ?, ?)",
        objectId,
        caller.tenantId(),
        issuerId.trim(),
        displayName == null ? "" : displayName,
        caller.name());
    sealVersion(caller, objectId, issuerId.trim(), 1, authorized, bytes);
    audit.record(
        caller,
        Action.VAULT_STORE_OBJECT,
        ResourceRef.tenantScoped("vault-object", objectId.toString(), caller.tenantId()),
        decision,
        "",
        Map.of("version", "1", "purposes", String.join(",", authorized)));
    return new StoredVersion(objectId, 1);
  }

  @Transactional(noRollbackFor = {ForbiddenException.class, VaultAuthenticationException.class})
  public StoredVersion storeVersion(
      ServiceAccountPrincipal caller,
      UUID objectId,
      List<String> purposes,
      byte[] content,
      String expectedSha256Hex) {
    Decision decision = require(caller, Action.VAULT_STORE_OBJECT, "vault-object",
        objectId.toString());
    List<String> authorized = validatedPurposes(purposes);
    byte[] bytes = validatedContent(content, expectedSha256Hex);
    String issuerId = issuerOf(objectId, caller.tenantId());
    // Serialize version allocation per object: concurrent writers get
    // distinct versions, never a duplicate-key race (SEC-34).
    tenant.execute("SELECT pg_advisory_xact_lock(hashtext('" + objectId + ":version'))");
    Integer max = tenant.queryForObject(
        "SELECT COALESCE(MAX(version), 0) FROM vault_object_version WHERE object_id = ?",
        Integer.class, objectId);
    int version = (max == null ? 0 : max) + 1;
    sealVersion(caller, objectId, issuerId, version, authorized, bytes);
    audit.record(
        caller,
        Action.VAULT_STORE_OBJECT,
        ResourceRef.tenantScoped("vault-object", objectId.toString(), caller.tenantId()),
        decision,
        "",
        Map.of("version", String.valueOf(version), "purposes", String.join(",", authorized)));
    return new StoredVersion(objectId, version);
  }

  @Transactional(noRollbackFor = {ForbiddenException.class, VaultAuthenticationException.class})
  public ObjectMetadata metadata(ServiceAccountPrincipal caller, UUID objectId) {
    Decision decision = require(caller, Action.VAULT_READ_METADATA, "vault-object",
        objectId.toString());
    List<Map<String, Object>> objects = tenant.queryForList(
        "SELECT issuer_id, display_name FROM vault_object WHERE id = ? AND tenant_id = ?",
        objectId, caller.tenantId());
    if (objects.isEmpty()) {
      throw new VaultNotFoundException();
    }
    List<VersionMetadata> versions = tenant.query(
        "SELECT version, authorized_purposes, kek_version, status, content_sha256, created_at"
            + " FROM vault_object_version WHERE object_id = ? ORDER BY version",
        (rs, row) -> new VersionMetadata(
            rs.getInt("version"),
            sorted(rs.getArray("authorized_purposes")),
            rs.getInt("kek_version"),
            rs.getString("status"),
            hex(rs.getBytes("content_sha256")),
            rs.getTimestamp("created_at").toInstant()),
        objectId);
    audit.record(
        caller, Action.VAULT_READ_METADATA,
        ResourceRef.tenantScoped("vault-object", objectId.toString(), caller.tenantId()),
        decision, "", Map.of("versions", String.valueOf(versions.size())));
    return new ObjectMetadata(objectId, (String) objects.get(0).get("issuer_id"),
        (String) objects.get(0).get("display_name"), versions);
  }

  @Transactional(noRollbackFor = {ForbiddenException.class, VaultAuthenticationException.class})
  public GrantView grant(
      ServiceAccountPrincipal caller,
      UUID objectId,
      int version,
      String principalType,
      UUID principalId,
      String purpose,
      String workload,
      long ttlSeconds) {
    Decision decision =
        require(caller, Action.VAULT_GRANT_ACCESS, "vault-grant", objectId.toString());
    StoredRow row = versionRow(objectId, version);
    if (!"VALID".equals(row.status())) {
      throw new VaultNotFoundException();
    }
    if (!"service_account".equals(principalType) && !"human_membership".equals(principalType)) {
      throw new VaultInvalidException("unknown principal type");
    }
    requireName(purpose, "purpose");
    requireName(workload, "workload");
    if (!row.purposes().contains(purpose)) {
      // Grants cannot widen an object's authorized purposes; mint a
      // new version carrying the purpose instead.
      throw new VaultInvalidException("purpose is not authorized for this version");
    }
    if (ttlSeconds < MIN_GRANT_TTL_SECONDS || ttlSeconds > MAX_GRANT_TTL_SECONDS) {
      throw new VaultInvalidException("grant TTL must be 60..86400 seconds");
    }
    if (!principalLiveInTenant(principalType, principalId, caller.tenantId())) {
      throw new VaultNotFoundException();
    }
    Instant expiresAt = clock.instant().plusSeconds(ttlSeconds);
    UUID grantId = UUID.randomUUID();
    tenant.update(
        "INSERT INTO vault_grant (id, tenant_id, object_id, object_version, principal_type,"
            + " principal_id, purpose, workload, expires_at, created_by)"
            + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        grantId, caller.tenantId(), objectId, version, principalType, principalId, purpose,
        workload, java.sql.Timestamp.from(expiresAt), caller.name());
    Map<String, String> detail = new LinkedHashMap<>();
    detail.put("grant", grantId.toString());
    detail.put("purpose", purpose);
    detail.put("version", String.valueOf(version));
    audit.record(
        caller, Action.VAULT_GRANT_ACCESS,
        ResourceRef.tenantScoped("vault-grant", grantId.toString(), caller.tenantId()),
        decision, "", detail);
    return new GrantView(grantId, objectId, version, principalType, principalId, purpose,
        workload, false, expiresAt, clock.instant());
  }

  @Transactional(noRollbackFor = {ForbiddenException.class, VaultAuthenticationException.class})
  public GrantView revokeGrant(ServiceAccountPrincipal caller, UUID grantId) {
    Decision decision =
        require(caller, Action.VAULT_REVOKE_GRANT, "vault-grant", grantId.toString());
    GrantRow row = grantRow(grantId);
    if (!row.revoked()) {
      tenant.update("UPDATE vault_grant SET revoked = TRUE WHERE id = ?", grantId);
    }
    audit.record(
        caller, Action.VAULT_REVOKE_GRANT,
        ResourceRef.tenantScoped("vault-grant", grantId.toString(), caller.tenantId()),
        decision, "", Map.of("grant", grantId.toString()));
    return view(row, true);
  }

  @Transactional(noRollbackFor = {ForbiddenException.class, VaultAuthenticationException.class})
  public ReadResult read(
      ServiceAccountPrincipal caller,
      UUID objectId,
      int version,
      UUID grantId,
      String purpose,
      String workload) {
    Decision decision =
        require(caller, Action.VAULT_READ_OBJECT, "vault-object", objectId.toString());
    StoredRow row = versionRow(objectId, version);
    if (!"VALID".equals(row.status())) {
      throw new VaultNotFoundException();
    }
    if (row.purposes().contains(QUARANTINE_PURPOSE)) {
      // Unscanned input never leaves through the content endpoint,
      // grant or no grant; promotion re-seals it server-side.
      deny(caller, Action.VAULT_READ_OBJECT, objectId.toString(), decision,
          ReasonCode.GRANT_INVALID);
      throw new ForbiddenException(ReasonCode.GRANT_INVALID);
    }
    GrantRow grant = grantRow(grantId);
    checkGrant(caller, grant, objectId, version, purpose, workload, decision);
    byte[] content = openAuthenticated(caller, row, purpose, decision);
    audit.record(
        caller, Action.VAULT_READ_OBJECT,
        ResourceRef.tenantScoped("vault-object", objectId.toString(), caller.tenantId()),
        decision, "",
        Map.of("version", String.valueOf(version), "purpose", purpose, "grant",
            grantId.toString()));
    return new ReadResult(content, version, hex(row.contentSha256()));
  }

  /**
   * Server-side quarantine open (SOV-017): mirrors {@link #read} but
   * accepts only quarantine-marked objects and never serves bytes to
   * a caller — the quarantine service re-seals them into a promoted
   * vault object. Same grant checks, same fail-closed integrity.
   */
  @Transactional(noRollbackFor = {ForbiddenException.class, VaultAuthenticationException.class})
  public byte[] readForQuarantine(
      ServiceAccountPrincipal caller,
      UUID objectId,
      int version,
      UUID grantId,
      String purpose,
      String workload) {
    Decision decision =
        require(caller, Action.VAULT_READ_OBJECT, "vault-object", objectId.toString());
    StoredRow row = versionRow(objectId, version);
    if (!"VALID".equals(row.status())) {
      throw new VaultNotFoundException();
    }
    if (!row.purposes().contains(QUARANTINE_PURPOSE)) {
      throw new VaultInvalidException("not a quarantine object");
    }
    GrantRow grant = grantRow(grantId);
    checkGrant(caller, grant, objectId, version, purpose, workload, decision);
    return openAuthenticated(caller, row, purpose, decision);
  }

  private byte[] openAuthenticated(
      ServiceAccountPrincipal caller,
      StoredRow row,
      String purpose,
      Decision decision) {
    try {
      byte[] wrapAad = wrapAad(caller.tenantId(), row);
      byte[] dek = kek.unwrapDek(
          caller.tenantId(), row.kekVersion(), row.wrappedDek(), row.dekNonce(), wrapAad);
      if (!row.purposes().contains(purpose)) {
        // Checked after the wrap opens, so the set compared is the
        // authenticated envelope set, not just the database row.
        deny(caller, Action.VAULT_READ_OBJECT, row.objectId().toString(), decision,
            ReasonCode.GRANT_INVALID);
        throw new ForbiddenException(ReasonCode.GRANT_INVALID);
      }
      return VaultCrypto.open(
          dek, row.contentNonce(), row.ciphertext(), contentAad(caller.tenantId(), row));
    } catch (VaultAuthenticationException e) {
      audit.record(
          caller, Action.VAULT_READ_OBJECT,
          ResourceRef.tenantScoped("vault-object", row.objectId().toString(),
              caller.tenantId()),
          Decision.deny(ReasonCode.VAULT_INTEGRITY_FAILURE, decision.policyVersion()),
          "", Map.of("version", String.valueOf(row.version())));
      throw e;
    }
  }

  @Transactional(noRollbackFor = {ForbiddenException.class, VaultAuthenticationException.class})
  public int rotateKek(ServiceAccountPrincipal caller) {
    Decision decision = require(caller, Action.VAULT_ROTATE_KEK, "vault-kek", "rotate");
    tenant.execute(
        "SELECT pg_advisory_xact_lock(hashtext('" + caller.tenantId() + ":kek'))");
    Integer max = tenant.queryForObject(
        "SELECT COALESCE(MAX(version), 0) FROM vault_kek WHERE tenant_id = ?",
        Integer.class, caller.tenantId());
    int version = (max == null ? 0 : max) + 1;
    tenant.update(
        "INSERT INTO vault_kek (tenant_id, version) VALUES (?, ?)",
        caller.tenantId(), version);
    audit.record(
        caller, Action.VAULT_ROTATE_KEK,
        ResourceRef.tenantScoped("vault-kek", String.valueOf(version), caller.tenantId()),
        decision, "", Map.of("version", String.valueOf(version)));
    return version;
  }

  @Transactional(noRollbackFor = {ForbiddenException.class, VaultAuthenticationException.class})
  public void deleteVersion(ServiceAccountPrincipal caller, UUID objectId, int version) {
    Decision decision = require(caller, Action.VAULT_DELETE_VERSION, "vault-object",
        objectId.toString());
    StoredRow row = versionRow(objectId, version);
    if ("VALID".equals(row.status())) {
      tenant.update(
          "UPDATE vault_object_version SET status = 'DELETED', status_updated_at = now()"
              + " WHERE object_id = ? AND version = ?",
          objectId, version);
    }
    audit.record(
        caller, Action.VAULT_DELETE_VERSION,
        ResourceRef.tenantScoped("vault-object", objectId.toString(), caller.tenantId()),
        decision, "", Map.of("version", String.valueOf(version)));
  }

  private void sealVersion(
      ServiceAccountPrincipal caller,
      UUID objectId,
      String issuerId,
      int version,
      List<String> purposes,
      byte[] content) {
    int kekVersion = ensureActiveKek(caller.tenantId());
    byte[] sha = VaultCrypto.sha256(content);
    byte[] dek = VaultCrypto.freshDek();
    byte[] contentNonce = VaultCrypto.freshNonce();
    StoredRow aad = new StoredRow(objectId, version, issuerId, purposes, sha, kekVersion,
        new byte[0], new byte[0], contentNonce, new byte[0], "VALID");
    byte[] ciphertext =
        VaultCrypto.seal(dek, contentNonce, content, contentAad(caller.tenantId(), aad));
    VaultKekProvider.WrappedDek wrapped =
        kek.wrapDek(caller.tenantId(), kekVersion, dek, wrapAad(caller.tenantId(), aad));
    tenant.update(
        "INSERT INTO vault_object_version (object_id, version, tenant_id, issuer_id,"
            + " authorized_purposes, content_sha256, kek_version, wrapped_dek, dek_nonce,"
            + " content_nonce, ciphertext, created_by)"
            + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        objectId, version, caller.tenantId(), issuerId,
        purposes.toArray(new String[0]), sha, kekVersion, wrapped.wrapped(), wrapped.nonce(),
        contentNonce, ciphertext, caller.name());
  }

  private int ensureActiveKek(UUID tenantId) {
    Integer max = tenant.queryForObject(
        "SELECT COALESCE(MAX(version), 0) FROM vault_kek"
            + " WHERE tenant_id = ? AND status = 'ACTIVE'",
        Integer.class, tenantId);
    if (max != null && max > 0) {
      return max;
    }
    tenant.update(
        "INSERT INTO vault_kek (tenant_id, version) VALUES (?, 1) ON CONFLICT DO NOTHING",
        tenantId);
    Integer created = tenant.queryForObject(
        "SELECT COALESCE(MAX(version), 0) FROM vault_kek"
            + " WHERE tenant_id = ? AND status = 'ACTIVE'",
        Integer.class, tenantId);
    if (created == null || created == 0) {
      throw new IllegalStateException("no active wrapping key for tenant");
    }
    return created;
  }

  private byte[] contentAad(UUID tenantId, StoredRow row) {
    return VaultEnvelope.contentAad(tenantId, row.issuerId(), row.objectId(), row.version(),
        row.kekVersion(), row.contentSha256());
  }

  private byte[] wrapAad(UUID tenantId, StoredRow row) {
    return VaultEnvelope.wrapAad(tenantId, row.issuerId(), row.objectId(), row.version(),
        row.kekVersion(), row.purposes());
  }

  private void checkGrant(
      ServiceAccountPrincipal caller,
      GrantRow grant,
      UUID objectId,
      int version,
      String purpose,
      String workload,
      Decision decision) {
    if (!grant.objectId().equals(objectId)
        || grant.objectVersion() != version
        || !"service_account".equals(grant.principalType())
        || !grant.principalId().equals(caller.id())
        || !grant.purpose().equals(purpose)
        || !grant.workload().equals(workload)) {
      deny(caller, Action.VAULT_READ_OBJECT, objectId.toString(), decision,
          ReasonCode.GRANT_INVALID);
      throw new ForbiddenException(ReasonCode.GRANT_INVALID);
    }
    if (grant.revoked()) {
      deny(caller, Action.VAULT_READ_OBJECT, objectId.toString(), decision,
          ReasonCode.GRANT_REVOKED);
      throw new ForbiddenException(ReasonCode.GRANT_REVOKED);
    }
    if (!grant.expiresAt().isAfter(clock.instant())) {
      deny(caller, Action.VAULT_READ_OBJECT, objectId.toString(), decision,
          ReasonCode.GRANT_EXPIRED);
      throw new ForbiddenException(ReasonCode.GRANT_EXPIRED);
    }
  }

  private void deny(
      ServiceAccountPrincipal caller,
      Action action,
      String resourceId,
      Decision decision,
      ReasonCode reason) {
    audit.recordDenial(
        caller, action,
        ResourceRef.tenantScoped("vault-object", resourceId, caller.tenantId()),
        reason, decision.policyVersion());
  }

  private Decision require(ServiceAccountPrincipal caller, Action action, String type, String id) {
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

  private String issuerOf(UUID objectId, UUID tenantId) {
    List<String> issuers = tenant.query(
        "SELECT issuer_id FROM vault_object WHERE id = ? AND tenant_id = ?",
        (rs, row) -> rs.getString(1), objectId, tenantId);
    if (issuers.isEmpty()) {
      throw new VaultNotFoundException();
    }
    return issuers.get(0);
  }

  private StoredRow versionRow(UUID objectId, int version) {
    List<StoredRow> rows = tenant.query(
        "SELECT object_id, version, issuer_id, authorized_purposes, content_sha256,"
            + " kek_version, wrapped_dek, dek_nonce, content_nonce, ciphertext, status"
            + " FROM vault_object_version WHERE object_id = ? AND version = ?",
        (rs, row) -> new StoredRow(
            rs.getObject("object_id", UUID.class),
            rs.getInt("version"),
            rs.getString("issuer_id"),
            sorted(rs.getArray("authorized_purposes")),
            rs.getBytes("content_sha256"),
            rs.getInt("kek_version"),
            rs.getBytes("wrapped_dek"),
            rs.getBytes("dek_nonce"),
            rs.getBytes("content_nonce"),
            rs.getBytes("ciphertext"),
            rs.getString("status")),
        objectId, version);
    if (rows.isEmpty()) {
      throw new VaultNotFoundException();
    }
    return rows.get(0);
  }

  private GrantRow grantRow(UUID grantId) {
    List<GrantRow> rows = tenant.query(
        "SELECT id, object_id, object_version, principal_type, principal_id, purpose,"
            + " workload, revoked, expires_at, created_at FROM vault_grant WHERE id = ?",
        (rs, row) -> new GrantRow(
            rs.getObject("id", UUID.class),
            rs.getObject("object_id", UUID.class),
            rs.getInt("object_version"),
            rs.getString("principal_type"),
            rs.getObject("principal_id", UUID.class),
            rs.getString("purpose"),
            rs.getString("workload"),
            rs.getBoolean("revoked"),
            rs.getTimestamp("expires_at").toInstant(),
            rs.getTimestamp("created_at").toInstant()),
        grantId);
    if (rows.isEmpty()) {
      throw new VaultNotFoundException();
    }
    return rows.get(0);
  }

  private GrantView view(GrantRow row, boolean revoked) {
    return new GrantView(row.id(), row.objectId(), row.objectVersion(), row.principalType(),
        row.principalId(), row.purpose(), row.workload(), revoked, row.expiresAt(),
        row.createdAt());
  }

  private boolean principalLiveInTenant(String type, UUID id, UUID tenantId) {
    if ("service_account".equals(type)) {
      return accounts.findLive(id)
          .filter(row -> row.tenantId().equals(tenantId) && row.live(clock.instant()))
          .isPresent();
    }
    return humans.findLive(id)
        .filter(row -> row.tenantId().equals(tenantId) && row.live())
        .isPresent();
  }

  private List<String> validatedPurposes(List<String> purposes) {
    if (purposes == null || purposes.isEmpty() || purposes.size() > 16) {
      throw new VaultInvalidException("1..16 authorized purposes are required");
    }
    for (String purpose : purposes) {
      requireName(purpose, "purpose");
    }
    return purposes.stream().sorted().distinct().toList();
  }

  private byte[] validatedContent(byte[] content, String expectedSha256Hex) {
    if (content == null || content.length == 0 || content.length > MAX_CONTENT_BYTES) {
      throw new VaultInvalidException("content must be 1..16777200 bytes");
    }
    if (expectedSha256Hex != null
        && !hex(VaultCrypto.sha256(content)).equals(expectedSha256Hex.toLowerCase())) {
      throw new VaultInvalidException("content does not match the pinned digest");
    }
    return content;
  }

  private static void requireText(String value, String name) {
    if (value == null || value.isBlank() || value.length() > 512) {
      throw new VaultInvalidException(name + " is required");
    }
  }

  private static void requireName(String value, String name) {
    if (value == null || !NAME.matcher(value).matches()) {
      throw new VaultInvalidException(name + " must match [a-z0-9-]{1,64}");
    }
  }

  private static List<String> sorted(java.sql.Array array) throws java.sql.SQLException {
    if (array == null) {
      return List.of();
    }
    String[] values = (String[]) array.getArray();
    Arrays.sort(values);
    return List.of(values);
  }

  private static String hex(byte[] bytes) {
    StringBuilder hex = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      hex.append(Character.forDigit((b >> 4) & 0xF, 16));
      hex.append(Character.forDigit(b & 0xF, 16));
    }
    return hex.toString();
  }
}
