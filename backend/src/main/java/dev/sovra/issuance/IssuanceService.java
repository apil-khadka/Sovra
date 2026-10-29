package dev.sovra.issuance;

import com.nimbusds.jose.util.Base64URL;
import dev.sovra.audit.AuditService;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ResourceRef;
import dev.sovra.crypto.HolderProofException;
import dev.sovra.crypto.HolderProofs;
import dev.sovra.crypto.P256;
import dev.sovra.ops.TelemetryService;
import dev.sovra.trust.IssuerKeyService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Issuer-scoped issuance (SOV-009). Issues only allowlisted claims for
 * issuers the active trust snapshot authorizes, binds credential ID,
 * holder, key version, validity and status, and replays idempotent
 * retries byte-for-byte. The credential, its idempotency record, and
 * the audit row commit atomically: if the evidence cannot commit,
 * nothing is issued.
 */
@Service
public class IssuanceService {

  static final Duration IDEMPOTENCY_TTL = Duration.ofHours(24);
  static final Duration MAX_VALIDITY = Duration.ofDays(366);
  static final Duration MIN_VALIDITY = Duration.ofMinutes(1);
  static final String PROOF_LABEL = "sovra-issuance-proof/v1";

  private final AuthorizationService authz;
  private final AuditService audit;
  private final TrustSnapshotProvider snapshots;
  private final IssuerKeyService keyService;
  private final StatusEvidenceFetcher status;
  private final CredentialEncoder encoder;
  private final JdbcTemplate tenant;
  private final Clock clock;
  private final ObjectMapper mapper;
  private final TelemetryService telemetry;

  public IssuanceService(
      AuthorizationService authz,
      AuditService audit,
      TrustSnapshotProvider snapshots,
      IssuerKeyService keyService,
      StatusEvidenceFetcher status,
      CredentialEncoder encoder,
      JdbcTemplate tenantJdbcTemplate,
      Clock clock,
      ObjectMapper mapper,
      TelemetryService telemetry) {
    this.authz = authz;
    this.audit = audit;
    this.snapshots = snapshots;
    this.keyService = keyService;
    this.status = status;
    this.encoder = encoder;
    this.tenant = tenantJdbcTemplate;
    this.clock = clock;
    this.mapper = mapper;
    this.telemetry = telemetry;
  }

  public record IssueRequest(
      String issuerId,
      String vct,
      JsonNode holderJwk,
      String holderProof,
      Map<String, Object> claims,
      Instant expiresAt) {}

  public record CredentialView(
      UUID credentialId,
      String issuerId,
      String vct,
      String keyRef,
      Instant issuedAt,
      Instant expiresAt,
      String status,
      long trustSnapshot) {}

  public record StatusView(String status, long version, Instant fetchedAt, long maxAgeSeconds) {}

  /**
   * Issues a credential or replays the original response byte-for-byte.
   * Returns the exact response body to send.
   */
  @Transactional
  public String issue(ServiceAccountPrincipal caller, IssueRequest request, String idempotencyKey) {
    // One sanitized timing sample per call; the transaction boundary stays
    // on this public method so proxy semantics are unchanged.
    return telemetry.time(
        caller.tenantId(),
        TelemetryService.Stage.ISSUANCE_ISSUE,
        Set.of(InvalidIssuanceException.class, TrustUnavailableException.class,
            IdempotencyConflictException.class, SigningRefusedException.class),
        () -> issueInner(caller, request, idempotencyKey, null, Action.ISSUE_CREDENTIAL));
  }

  /**
   * OpenID4VCI issuance (SOV-036). Identical gates to {@link #issue},
   * except the holder proof is an OpenID4VCI {@code jwt} proof bound to
   * the token's single-use {@code c_nonce} instead of the Sovra proof
   * message. The VCI service consumes the {@code c_nonce} before
   * delegating here; this method verifies the proof itself, so no
   * caller can reach encoding without a valid proof.
   *
   * <p>{@code grantAuthority} is the authority behind the redeemed
   * grant: {@code ISSUE_CREDENTIAL} for pre-authorized redemptions
   * (issuer-operator authority) or {@code VCI_AUTHORIZE} for
   * authorization-code redemptions (synthetic-AS holder authority).
   * Anything else is rejected.
   */
  @Transactional
  public String issueVci(
      ServiceAccountPrincipal caller, IssueRequest request, String idempotencyKey,
      String cNonce, Action grantAuthority) {
    if (cNonce == null || cNonce.isBlank()) {
      throw new InvalidIssuanceException("credential nonce is missing");
    }
    if (grantAuthority != Action.ISSUE_CREDENTIAL && grantAuthority != Action.VCI_AUTHORIZE) {
      throw new IllegalArgumentException("vci grant authority is not issuable");
    }
    return telemetry.time(
        caller.tenantId(),
        TelemetryService.Stage.ISSUANCE_ISSUE,
        Set.of(InvalidIssuanceException.class, TrustUnavailableException.class,
            IdempotencyConflictException.class, SigningRefusedException.class),
        () -> issueInner(caller, request, idempotencyKey, cNonce, grantAuthority));
  }

  private String issueInner(
      ServiceAccountPrincipal caller, IssueRequest request, String idempotencyKey,
      String vciNonce, Action authority) {
    ResourceRef resource =
        ResourceRef.tenantScoped("credential", "issuance", caller.tenantId());
    Decision decision = authz.authorize(Optional.of(caller), authority, resource);
    if (!decision.permitted()) {
      audit.recordDenial(caller, authority, resource, decision.reasonCode(),
          decision.policyVersion());
      throw new ForbiddenException(decision.reasonCode());
    }
    if (idempotencyKey == null || !idempotencyKey.matches("[A-Za-z0-9_-]{1,128}")) {
      throw new InvalidIssuanceException("idempotency key is malformed");
    }
    Instant now = clock.instant();
    Validated validated = validate(request, idempotencyKey, now, vciNonce);
    String hash = requestHash(request, validated.holderKey());

    Optional<String> replay =
        checkIdempotency(caller, decision, authority, idempotencyKey, hash, now);
    if (replay.isPresent()) {
      return replay.get();
    }

    var snapshot = snapshots.current().orElseThrow(TrustUnavailableException::new);
    IssuerAuthorization authorization = authorizeIssuer(snapshot, request, now);

    UUID credentialId = UUID.randomUUID();
    String statusUri = "/api/issuance/credentials/" + credentialId + "/status";
    IssuanceEvidence evidence =
        new IssuanceEvidence(
            credentialId, request.issuerId(), authorization.keyRef(), request.vct(),
            Map.of("adultOver18", Boolean.TRUE), validated.thumbprint(),
            now, request.expiresAt(), snapshot.version(), statusUri,
            request.holderJwk());
    CredentialEncoder.EncodedCredential encoded = encoder.encode(evidence);

    String response = responseBody(credentialId, encoded.artifact(), request.expiresAt(),
        snapshot.version());
    // A savepoint around the contested writes: PostgreSQL aborts the
    // whole transaction on a unique violation, so the loser rolls back
    // to the savepoint — discarding its orphan credential row — before
    // reconciling against the winner's idempotency record. Same shape
    // as VerificationService. The savepoint rides the
    // transaction-bound connection, so this works for
    // container-managed and programmatic transactions alike.
    java.sql.Connection connection = DataSourceUtils.getConnection(tenant.getDataSource());
    java.sql.Savepoint savepoint;
    try {
      savepoint = connection.setSavepoint();
    } catch (java.sql.SQLException e) {
      DataSourceUtils.releaseConnection(connection, tenant.getDataSource());
      throw new IllegalStateException("savepoint failed", e);
    }
    try {
      tenant.update(
          "INSERT INTO credential_artifact (id, tenant_id, issuer_id, vct, holder_thumbprint,"
              + " key_ref, issued_at, expires_at, status, artifact, trust_snapshot_version,"
              + " created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'VALID', ?, ?, ?)",
          credentialId, caller.tenantId(), request.issuerId(), request.vct(),
          validated.thumbprint(), authorization.keyRef().encode(),
          java.sql.Timestamp.from(now), java.sql.Timestamp.from(request.expiresAt()),
          encoded.artifact(), snapshot.version(), caller.name());
      tenant.update(
          "INSERT INTO issuance_idempotency (tenant_id, idempotency_key, credential_id,"
              + " request_hash, response_body, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
          caller.tenantId(), idempotencyKey, credentialId, hash, response,
          java.sql.Timestamp.from(now.plus(IDEMPOTENCY_TTL)));
      connection.releaseSavepoint(savepoint);
    } catch (DuplicateKeyException e) {
      // Lost a race with the same key: reconcile against durable state.
      try {
        connection.rollback(savepoint);
      } catch (java.sql.SQLException rollback) {
        throw new IllegalStateException("savepoint rollback failed", rollback);
      }
      return checkIdempotency(caller, decision, authority, idempotencyKey, hash, now)
          .orElseThrow(() -> new IllegalStateException("idempotency record vanished"));
    } catch (RuntimeException e) {
      try {
        connection.rollback(savepoint);
      } catch (java.sql.SQLException rollback) {
        e.addSuppressed(rollback);
      }
      throw e;
    } catch (java.sql.SQLException e) {
      throw new IllegalStateException("savepoint release failed", e);
    } finally {
      DataSourceUtils.releaseConnection(connection, tenant.getDataSource());
    }
    audit.record(caller, authority, resource, decision, "",
        detail(credentialId, request, authorization.keyRef(), snapshot.version(), false));
    return response;
  }

  private Optional<String> checkIdempotency(
      ServiceAccountPrincipal caller, Decision decision, Action authority, String key, String hash,
      Instant now) {
    List<IdempotencyRow> rows =
        tenant.query(
            "SELECT credential_id, request_hash, response_body, expires_at"
                + " FROM issuance_idempotency WHERE tenant_id = ? AND idempotency_key = ?",
            (rs, row) ->
                new IdempotencyRow(
                    rs.getObject("credential_id", UUID.class),
                    rs.getString("request_hash"),
                    rs.getString("response_body"),
                    rs.getTimestamp("expires_at").toInstant()),
            caller.tenantId(), key);
    if (rows.isEmpty()) {
      return Optional.empty();
    }
    IdempotencyRow row = rows.get(0);
    if (!row.expiresAt().isAfter(now)) {
      // Retention lapsed: reclaim the key; the credential row lives on.
      tenant.update(
          "DELETE FROM issuance_idempotency WHERE tenant_id = ? AND idempotency_key = ?",
          caller.tenantId(), key);
      return Optional.empty();
    }
    if (!row.requestHash().equals(hash)) {
      throw new IdempotencyConflictException();
    }
    audit.record(
        caller, authority,
        ResourceRef.tenantScoped("credential", row.credentialId().toString(), caller.tenantId()),
        decision, "", Map.of("credential", row.credentialId().toString(), "replay", "true"));
    return Optional.of(row.responseBody());
  }

  private record IdempotencyRow(UUID credentialId, String requestHash, String responseBody,
      Instant expiresAt) {}

  private Map<String, String> detail(
      UUID credentialId, IssueRequest request, KeyRef keyRef, long snapshot, boolean replay) {
    Map<String, String> detail = new LinkedHashMap<>();
    detail.put("credential", credentialId.toString());
    detail.put("issuer", request.issuerId());
    detail.put("vct", request.vct());
    detail.put("key", keyRef.encode());
    detail.put("snapshot", String.valueOf(snapshot));
    detail.put("replay", String.valueOf(replay));
    return detail;
  }

  private String responseBody(UUID credentialId, String artifact, Instant expiresAt, long snapshot) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("credentialId", credentialId.toString());
    body.put("artifact", artifact);
    body.put("status", "VALID");
    body.put("expiresAt", expiresAt.toString());
    body.put("trustSnapshot", snapshot);
    try {
      return mapper.writeValueAsString(body);
    } catch (JacksonException e) {
      throw new IllegalStateException(e);
    }
  }

  private String requestHash(IssueRequest request, ECPublicKey holderKey) {
    String canonical =
        request.issuerId() + "\n" + request.vct() + "\n"
            + holderKey.getW().getAffineX().toString(16) + "\n"
            + holderKey.getW().getAffineY().toString(16) + "\n"
            + "adultOver18=true\n" + request.expiresAt().toString();
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Canonical proof message. The holder consents to the exact claims, not
   * just the credential type; the allowlist check above guarantees the
   * normalized form matches the request.
   */
  static String proofMessage(String idempotencyKey, IssueRequest request, String thumbprint) {
    return PROOF_LABEL + "\n" + idempotencyKey + "\n" + request.vct() + "\n" + thumbprint + "\n"
        + "adultOver18=true";
  }

  private record Validated(ECPublicKey holderKey, String thumbprint) {}
  private record IssuerAuthorization(KeyRef keyRef) {}

  /** Shape, allowlist, holder-key, proof-of-possession, and validity checks. */
  private Validated validate(
      IssueRequest request, String idempotencyKey, Instant now, String vciNonce) {
    if (request == null
        || request.issuerId() == null || request.issuerId().isBlank()
        || request.vct() == null || request.vct().isBlank()
        || request.holderJwk() == null
        || request.holderProof() == null || request.holderProof().isBlank()
        || request.expiresAt() == null) {
      throw new InvalidIssuanceException("issuance request is incomplete");
    }
    SyntheticJwtEncoder.allowlistClaims(request.vct(), request.claims());
    if (!request.expiresAt().isAfter(now.plus(MIN_VALIDITY))
        || request.expiresAt().isAfter(now.plus(MAX_VALIDITY))) {
      throw new InvalidIssuanceException("validity is outside the permitted range");
    }
    ECPublicKey holderKey = holderKey(request.holderJwk());
    String thumbprint =
        P256.thumbprint(holderKey.getW().getAffineX(), holderKey.getW().getAffineY());
    if (vciNonce != null) {
      verifyVciProof(holderKey, request, vciNonce, now);
    } else {
      verifyProof(
          holderKey, request.holderProof(), proofMessage(idempotencyKey, request, thumbprint));
    }
    return new Validated(holderKey, thumbprint);
  }

  /**
   * Shared holder-key parsing, translated to the issuance domain
   * error. The checks live in {@link HolderProofs}; this seam only
   * preserves the issuance HTTP mapping.
   */
  private ECPublicKey holderKey(JsonNode jwk) {
    try {
      return HolderProofs.parseP256Key(jwk);
    } catch (HolderProofException e) {
      throw new InvalidIssuanceException(e.getMessage());
    }
  }

  private static String text(JsonNode node, String field) {
    JsonNode child = node == null ? null : node.get(field);
    return child != null && child.isString() ? child.asString() : null;
  }

  /**
   * Holder proof of possession: ES256 over the canonical proof
   * message. Delegates to the shared checks; the wording is
   * identical on both sides, so translation is exact.
   */
  private void verifyProof(ECPublicKey holderKey, String proof, String expectedMessage) {
    try {
      HolderProofs.verifyEs256(holderKey, proof, expectedMessage, mapper);
    } catch (HolderProofException e) {
      throw new InvalidIssuanceException(e.getMessage());
    }
  }

  /**
   * OpenID4VCI {@code jwt} proof (SOV-036): ES256, {@code typ}
   * {@code openid4vci-proof+jwt}, holder key in the {@code jwk} header
   * matching the request key, {@code aud} naming this credential
   * issuer, and {@code nonce} equal to the token's single-use
   * {@code c_nonce}. Freshness comes from the single-use nonce; the
   * {@code iat} must additionally sit inside the 5-minute skew window.
   */
  private void verifyVciProof(
      ECPublicKey holderKey, IssueRequest request, String cNonce, Instant now) {
    try {
      String[] parts = request.holderProof().split("\\.", -1);
      if (parts.length != 3) {
        throw new InvalidIssuanceException("holder proof is malformed");
      }
      JsonNode header = mapper.readTree(Base64URL.from(parts[0]).decode());
      if (!"ES256".equals(text(header, "alg"))
          || !"openid4vci-proof+jwt".equals(text(header, "typ"))) {
        throw new InvalidIssuanceException("holder proof must be an ES256 VCI proof JWT");
      }
      JsonNode proofJwk = header.get("jwk");
      if (proofJwk == null || !proofJwk.isObject()) {
        throw new InvalidIssuanceException("holder proof must carry its key");
      }
      ECPublicKey proofKey = holderKey(proofJwk);
      if (!proofKey.getW().getAffineX().equals(holderKey.getW().getAffineX())
          || !proofKey.getW().getAffineY().equals(holderKey.getW().getAffineY())) {
        throw new InvalidIssuanceException("holder proof key does not match this request");
      }
      JsonNode body = mapper.readTree(Base64URL.from(parts[1]).decode());
      if (!request.issuerId().equals(text(body, "aud"))) {
        throw new InvalidIssuanceException("holder proof audience is wrong");
      }
      if (!MessageDigest.isEqual(
          String.valueOf(text(body, "nonce")).getBytes(StandardCharsets.UTF_8),
          cNonce.getBytes(StandardCharsets.UTF_8))) {
        throw new InvalidIssuanceException("holder proof nonce is wrong");
      }
      JsonNode iat = body.get("iat");
      if (iat == null || !iat.isNumber()
          || Math.abs(now.getEpochSecond() - iat.asLong()) > 5 * 60) {
        throw new InvalidIssuanceException("holder proof is stale");
      }
      // Field checks above are VCI-specific; the signature tail is
      // the shared one. (A corrupt signature container surfaces as a
      // signature failure, which is the accurate wording here.)
      try {
        HolderProofs.verifySignature(holderKey, request.holderProof());
      } catch (HolderProofException e) {
        throw new InvalidIssuanceException("holder proof signature is invalid");
      }
    } catch (InvalidIssuanceException e) {
      throw e;
    } catch (JacksonException e) {
      throw new InvalidIssuanceException("holder proof is malformed");
    } catch (Exception e) {
      throw new InvalidIssuanceException("holder proof is invalid");
    }
  }

  /** Issuer, key, epoch, and type-scope checks against live trust state. */
  private IssuerAuthorization authorizeIssuer(
      dev.sovra.trust.TrustService.SnapshotView snapshot, IssueRequest request, Instant now) {
    var issuer =
        snapshot.issuers().stream()
            .filter(i -> request.issuerId().equals(i.issuerId()))
            .findFirst()
            .orElseThrow(() -> new InvalidIssuanceException("issuer is not trusted"));
    if (!"ACTIVE".equals(issuer.status())
        || issuer.validFrom().isAfter(now)
        || issuer.validThrough().isBefore(now)) {
      throw new InvalidIssuanceException("issuer is not trusted");
    }
    if (!issuer.credentialTypes().contains(request.vct())) {
      throw new InvalidIssuanceException("credential type is outside issuer scope");
    }
    // The snapshot pins the exact authorized key version; the live
    // registry check honors compromise and retirement (SOV-012).
    if (!dev.sovra.trust.IssuerKeys.active(
        tenant, request.issuerId(), issuer.keyId(), issuer.keyVersion())) {
      throw new InvalidIssuanceException("issuer signing key is not active");
    }
    return new IssuerAuthorization(
        new KeyRef(request.issuerId(), issuer.keyId(), issuer.keyVersion()));
  }

  public CredentialView get(ServiceAccountPrincipal caller, UUID credentialId) {
    ResourceRef resource = ResourceRef.tenantScoped("credential", credentialId.toString(),
        caller.tenantId());
    Decision decision = authz.authorize(Optional.of(caller), Action.READ_CREDENTIAL, resource);
    if (!decision.permitted()) {
      audit.recordDenial(caller, Action.READ_CREDENTIAL, resource, decision.reasonCode(),
          decision.policyVersion());
      throw new ForbiddenException(decision.reasonCode());
    }
    List<CredentialView> rows =
        tenant.query(
            "SELECT id, issuer_id, vct, key_ref, issued_at, expires_at, status,"
                + " trust_snapshot_version FROM credential_artifact"
                + " WHERE id = ? AND tenant_id = ?",
            (rs, row) ->
                new CredentialView(
                    rs.getObject("id", UUID.class),
                    rs.getString("issuer_id"),
                    rs.getString("vct"),
                    rs.getString("key_ref"),
                    rs.getTimestamp("issued_at").toInstant(),
                    rs.getTimestamp("expires_at").toInstant(),
                    rs.getString("status"),
                    rs.getLong("trust_snapshot_version")),
            credentialId,
            caller.tenantId());
    if (rows.isEmpty()) {
      throw new CredentialNotFoundException();
    }
    return rows.get(0);
  }

  public StatusView status(ServiceAccountPrincipal caller, UUID credentialId) {
    ResourceRef resource = ResourceRef.tenantScoped("credential", credentialId.toString(),
        caller.tenantId());
    Decision decision = authz.authorize(Optional.of(caller), Action.READ_CREDENTIAL, resource);
    if (!decision.permitted()) {
      audit.recordDenial(caller, Action.READ_CREDENTIAL, resource, decision.reasonCode(),
          decision.policyVersion());
      throw new ForbiddenException(decision.reasonCode());
    }
    var evidence = status.fetch(credentialId);
    return new StatusView(
        evidence.status().name(), evidence.version(), evidence.fetchedAt(),
        evidence.maxAge().toSeconds());
  }

  /** Terminal revocation: VALID becomes REVOKED, never the reverse. */
  @Transactional
  public StatusView revoke(ServiceAccountPrincipal caller, UUID credentialId) {
    ResourceRef resource = ResourceRef.tenantScoped("credential", credentialId.toString(),
        caller.tenantId());
    Decision decision = authz.authorize(Optional.of(caller), Action.ISSUE_CREDENTIAL, resource);
    if (!decision.permitted()) {
      audit.recordDenial(caller, Action.ISSUE_CREDENTIAL, resource, decision.reasonCode(),
          decision.policyVersion());
      throw new ForbiddenException(decision.reasonCode());
    }
    List<String> rows =
        tenant.query(
            "SELECT status FROM credential_artifact WHERE id = ? AND tenant_id = ?",
            (rs, row) -> rs.getString(1),
            credentialId,
            caller.tenantId());
    if (rows.isEmpty()) {
      throw new CredentialNotFoundException();
    }
    if ("VALID".equals(rows.get(0))) {
      // The status predicate makes concurrent revokes converge: only
      // the first flip bumps the version; losers re-read REVOKED.
      tenant.update(
          "UPDATE credential_artifact SET status = 'REVOKED', status_updated_at = ?,"
              + " status_version = status_version + 1"
              + " WHERE id = ? AND tenant_id = ? AND status = 'VALID'",
          java.sql.Timestamp.from(clock.instant()), credentialId, caller.tenantId());
    }
    audit.record(caller, Action.ISSUE_CREDENTIAL, resource, decision, "",
        Map.of("credential", credentialId.toString(), "revoked", "true"));
    var evidence = status.fetch(credentialId);
    return new StatusView(
        evidence.status().name(), evidence.version(), evidence.fetchedAt(),
        evidence.maxAge().toSeconds());
  }

  /**
   * Public federation metadata: verification keys of authorized
   * issuers, minus revoked key versions. The snapshots stay immutable
   * — this filter applies at serve time only — and unrevoked rotation
   * keys keep serving for their approved validity window. Removing a
   * key here is hygiene, not enforcement: verifiers check live key
   * status independently, since previously cached keys outlive any
   * single JWKS response.
   */
  public String jwks() {
    try {
      Instant now = clock.instant();
      List<JsonNode> keys =
          snapshots.current()
              .map(
                  snapshot ->
                      snapshot.issuers().stream()
                          .filter(
                              issuer ->
                                  "ACTIVE".equals(issuer.status())
                                      && !issuer.validFrom().isAfter(now)
                                      && !issuer.validThrough().isBefore(now)
                                      && !keyService.revoked(
                                          issuer.issuerId(),
                                          issuer.keyId(),
                                          issuer.keyVersion()))
                          .map(dev.sovra.trust.TrustService.IssuerView::publicKeyJwk)
                          .toList())
              .orElse(List.of());
      return mapper.writeValueAsString(Map.of("keys", keys));
    } catch (JacksonException e) {
      throw new IllegalStateException(e);
    }
  }
}
