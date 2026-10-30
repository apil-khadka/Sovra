package dev.sovra.trust;

import dev.sovra.audit.AuditService;
import dev.sovra.audit.AuditedAuthorizer;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ResourceRef;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Issuer key rotation and compromise lifecycle (SOV-012, FR-23).
 * Registration publishes a new key version; only a later two-person
 * snapshot activation authorizes it, so registration alone can never
 * widen trust. Revocation inserts a terminal revocation row — the app
 * role cannot update or delete it — and every signing, issuance, and
 * verification check honors it live (SR-29). Replacement keys take new
 * identifiers (SOV-001 section 4); a revoked version never signs again.
 */
@Service
public class IssuerKeyService {

  private final AuthorizationService authz;
  private final AuditService audit;
  private final JdbcTemplate global;
  private final Clock clock;
  private final ObjectMapper mapper;

  public IssuerKeyService(
      AuthorizationService authz,
      AuditService audit,
      DataSource globalDataSource,
      Clock clock,
      ObjectMapper mapper) {
    this.authz = authz;
    this.audit = audit;
    this.global = new JdbcTemplate(globalDataSource);
    this.clock = clock;
    this.mapper = mapper;
  }

  public record RegisterRequest(String issuerId, String keyId, int keyVersion, JsonNode publicKeyJwk) {}

  public record RevokeRequest(String issuerId, String keyId, int keyVersion, String reason) {}

  public record KeyView(
      String issuerId, String keyId, int keyVersion, KeyStatus status, Instant revokedAt) {}

  /**
   * Public revocation truth for serving federation metadata: a
   * revocation row terminally retires the key version. No caller
   * parameter: revocation state is public exactly like the JWKS it
   * filters, and verifiers enforce it independently anyway.
   */
  public boolean revoked(String issuerId, String keyId, int keyVersion) {
    Integer count =
        global.queryForObject(
            "SELECT COUNT(*) FROM issuer_key_revocation"
                + " WHERE issuer_id = ? AND key_id = ? AND key_version = ?",
            Integer.class,
            issuerId,
            keyId,
            keyVersion);
    return count != null && count > 0;
  }

  /** Publishes a key version; idempotent for byte-identical re-registration. */
  @Transactional
  public KeyView register(ServiceAccountPrincipal caller, RegisterRequest request) {
    ResourceRef resource = resource(request.issuerId(), request.keyId(), request.keyVersion());
    Decision decision = AuditedAuthorizer.require(authz, audit, caller,
        Action.REGISTER_ISSUER_KEY, resource);
    validateIdentity(request.issuerId(), request.keyId(), request.keyVersion());
    TrustProposalValidator.validateKey(request.keyId(), request.publicKeyJwk());
    String jwk = request.publicKeyJwk().toString();
    global.update(
        "INSERT INTO issuer_signing_key (issuer_id, key_id, key_version, public_key_jwk, status)"
            + " VALUES (?, ?, ?, ?::jsonb, 'ACTIVE') ON CONFLICT DO NOTHING",
        request.issuerId(), request.keyId(), request.keyVersion(), jwk);
    List<String> stored =
        global.query(
            "SELECT public_key_jwk::text FROM issuer_signing_key"
                + " WHERE issuer_id = ? AND key_id = ? AND key_version = ?",
            (rs, row) -> rs.getString(1),
            request.issuerId(), request.keyId(), request.keyVersion());
    // First writer wins: a later registration under the same identity
    // must name the same key, never shadow it.
    if (stored.size() != 1 || !sameKey(stored.get(0), jwk)) {
      throw new IssuerKeyConflictException();
    }
    audit.record(caller, Action.REGISTER_ISSUER_KEY, resource, decision, "",
        Map.of("key", keyName(request.issuerId(), request.keyId(), request.keyVersion())));
    return view(request.issuerId(), request.keyId(), request.keyVersion());
  }

  /**
   * Terminally revokes a key version. Idempotent: concurrent revokes
   * reconcile on the primary key and every caller observes the same
   * revocation instant, which is the containment evidence.
   */
  @Transactional
  public KeyView revoke(ServiceAccountPrincipal caller, RevokeRequest request) {
    ResourceRef resource = resource(request.issuerId(), request.keyId(), request.keyVersion());
    Decision decision = AuditedAuthorizer.require(authz, audit, caller,
        Action.REVOKE_ISSUER_KEY, resource);
    validateIdentity(request.issuerId(), request.keyId(), request.keyVersion());
    if (request.reason() == null
        || request.reason().isBlank()
        || request.reason().length() > 256) {
      throw new InvalidProposalException("revocation reason is required");
    }
    List<String> registered =
        global.query(
            "SELECT status FROM issuer_signing_key"
                + " WHERE issuer_id = ? AND key_id = ? AND key_version = ?",
            (rs, row) -> rs.getString(1),
            request.issuerId(), request.keyId(), request.keyVersion());
    if (registered.isEmpty()) {
      throw new IssuerKeyNotFoundException();
    }
    Instant now = clock.instant();
    global.update(
        "INSERT INTO issuer_key_revocation"
            + " (issuer_id, key_id, key_version, revoked_at, revoked_by, reason)"
            + " VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
        request.issuerId(), request.keyId(), request.keyVersion(),
        java.sql.Timestamp.from(now), caller.name(), request.reason());
    Instant revokedAt =
        global.queryForObject(
            "SELECT revoked_at FROM issuer_key_revocation"
                + " WHERE issuer_id = ? AND key_id = ? AND key_version = ?",
            (rs, row) -> rs.getTimestamp(1).toInstant(),
            request.issuerId(), request.keyId(), request.keyVersion());
    Map<String, String> detail = new LinkedHashMap<>();
    detail.put("key", keyName(request.issuerId(), request.keyId(), request.keyVersion()));
    detail.put("revoked_at", String.valueOf(revokedAt));
    detail.put("reason", request.reason());
    audit.record(caller, Action.REVOKE_ISSUER_KEY, resource, decision, "", detail);
    return new KeyView(
        request.issuerId(), request.keyId(), request.keyVersion(), KeyStatus.REVOKED, revokedAt);
  }

  private KeyView view(String issuerId, String keyId, int keyVersion) {
    List<Instant> revoked =
        global.query(
            "SELECT revoked_at FROM issuer_key_revocation"
                + " WHERE issuer_id = ? AND key_id = ? AND key_version = ?",
            (rs, row) -> rs.getTimestamp(1).toInstant(),
            issuerId, keyId, keyVersion);
    if (!revoked.isEmpty()) {
      return new KeyView(issuerId, keyId, keyVersion, KeyStatus.REVOKED, revoked.get(0));
    }
    return new KeyView(issuerId, keyId, keyVersion, KeyStatus.ACTIVE, null);
  }

  private static void validateIdentity(String issuerId, String keyId, int keyVersion) {
    if (issuerId == null || issuerId.isBlank() || issuerId.length() > 256
        || keyId == null || keyId.isBlank() || keyId.length() > 128 || keyId.contains(":")) {
      throw new InvalidProposalException("issuer key identity is malformed");
    }
    if (keyVersion < 1) {
      throw new InvalidProposalException("key version starts at 1");
    }
  }

  private static ResourceRef resource(String issuerId, String keyId, int keyVersion) {
    return ResourceRef.global("issuer-signing-key", keyName(issuerId, keyId, keyVersion));
  }

  private static String keyName(String issuerId, String keyId, int keyVersion) {
    return issuerId + ":" + keyId + ":v" + keyVersion;
  }

  /** JWK equality by parsed tree; formatting never shadows a key. */
  private boolean sameKey(String stored, String presented) {
    try {
      return mapper.readTree(stored).equals(mapper.readTree(presented));
    } catch (tools.jackson.core.JacksonException e) {
      throw new IllegalStateException("stored JWK is not JSON", e);
    }
  }
}
