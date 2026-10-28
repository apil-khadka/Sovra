package dev.sovra.issuance;

import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import dev.sovra.audit.AuditService;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ResourceRef;
import dev.sovra.ops.TelemetryService;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
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
      StatusEvidenceFetcher status,
      CredentialEncoder encoder,
      JdbcTemplate tenantJdbcTemplate,
      Clock clock,
      ObjectMapper mapper,
      TelemetryService telemetry) {
    this.authz = authz;
    this.audit = audit;
    this.snapshots = snapshots;
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
        () -> issueInner(caller, request, idempotencyKey));
  }

  private String issueInner(
      ServiceAccountPrincipal caller, IssueRequest request, String idempotencyKey) {
    ResourceRef resource =
        ResourceRef.tenantScoped("credential", "issuance", caller.tenantId());
    Decision decision = authz.authorize(Optional.of(caller), Action.ISSUE_CREDENTIAL, resource);
    if (!decision.permitted()) {
      audit.recordDenial(caller, Action.ISSUE_CREDENTIAL, resource, decision.reasonCode(),
          decision.policyVersion());
      throw new ForbiddenException(decision.reasonCode());
    }
    if (idempotencyKey == null || !idempotencyKey.matches("[A-Za-z0-9_-]{1,128}")) {
      throw new InvalidIssuanceException("idempotency key is malformed");
    }
    Instant now = clock.instant();
    Validated validated = validate(request, idempotencyKey, now);
    String hash = requestHash(request, validated.holderKey());

    Optional<String> replay = checkIdempotency(caller, decision, idempotencyKey, hash, now);
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
            now, request.expiresAt(), snapshot.version(), statusUri);
    CredentialEncoder.EncodedCredential encoded = encoder.encode(evidence);

    tenant.update(
        "INSERT INTO credential_artifact (id, tenant_id, issuer_id, vct, holder_thumbprint,"
            + " key_ref, issued_at, expires_at, status, artifact, trust_snapshot_version,"
            + " created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'VALID', ?, ?, ?)",
        credentialId, caller.tenantId(), request.issuerId(), request.vct(),
        validated.thumbprint(), authorization.keyRef().encode(),
        java.sql.Timestamp.from(now), java.sql.Timestamp.from(request.expiresAt()),
        encoded.artifact(), snapshot.version(), caller.name());

    String response = responseBody(credentialId, encoded.artifact(), request.expiresAt(),
        snapshot.version());
    try {
      tenant.update(
          "INSERT INTO issuance_idempotency (tenant_id, idempotency_key, credential_id,"
              + " request_hash, response_body, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
          caller.tenantId(), idempotencyKey, credentialId, hash, response,
          java.sql.Timestamp.from(now.plus(IDEMPOTENCY_TTL)));
    } catch (DuplicateKeyException e) {
      // Lost a race with the same key: reconcile against durable state.
      return checkIdempotency(caller, decision, idempotencyKey, hash, now)
          .orElseThrow(() -> new IllegalStateException("idempotency record vanished"));
    }
    audit.record(caller, Action.ISSUE_CREDENTIAL, resource, decision, "",
        detail(credentialId, request, authorization.keyRef(), snapshot.version(), false));
    return response;
  }

  private Optional<String> checkIdempotency(
      ServiceAccountPrincipal caller, Decision decision, String key, String hash, Instant now) {
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
        caller, Action.ISSUE_CREDENTIAL,
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
  private Validated validate(IssueRequest request, String idempotencyKey, Instant now) {
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
    ECPublicKey holderKey = parseHolderKey(request.holderJwk());
    String thumbprint =
        LocalDevSigner.thumbprint(holderKey.getW().getAffineX(), holderKey.getW().getAffineY());
    verifyProof(holderKey, request.holderProof(), proofMessage(idempotencyKey, request, thumbprint));
    return new Validated(holderKey, thumbprint);
  }

  private ECPublicKey parseHolderKey(JsonNode jwk) {
    try {
      if (!"EC".equals(text(jwk, "kty")) || !"P-256".equals(text(jwk, "crv"))) {
        throw new InvalidIssuanceException("holder key must be P-256");
      }
      BigInteger x = unsigned(text(jwk, "x"));
      BigInteger y = unsigned(text(jwk, "y"));
      ECParameterSpec params = LocalDevSigner.ECP256.params();
      KeyFactory factory = KeyFactory.getInstance("EC");
      return (ECPublicKey) factory.generatePublic(new ECPublicKeySpec(new ECPoint(x, y), params));
    } catch (InvalidIssuanceException e) {
      throw e;
    } catch (Exception e) {
      throw new InvalidIssuanceException("holder key is malformed");
    }
  }

  private static String text(JsonNode node, String field) {
    JsonNode child = node == null ? null : node.get(field);
    return child != null && child.isString() ? child.asString() : null;
  }

  private static BigInteger unsigned(String base64Url) {
    if (base64Url == null) {
      throw new InvalidIssuanceException("holder key is malformed");
    }
    byte[] raw;
    try {
      raw = Base64URL.from(base64Url).decode();
    } catch (Exception e) {
      throw new InvalidIssuanceException("holder key is malformed");
    }
    if (raw.length != 32) {
      throw new InvalidIssuanceException("holder key is malformed");
    }
    return new BigInteger(1, raw);
  }

  /** Holder proof of possession: ES256 over the canonical proof message. */
  private void verifyProof(ECPublicKey holderKey, String proof, String expectedMessage) {
    try {
      String[] parts = proof.split("\\.", -1);
      if (parts.length != 3) {
        throw new InvalidIssuanceException("holder proof is malformed");
      }
      JsonNode header = mapper.readTree(Base64URL.from(parts[0]).decode());
      if (!"ES256".equals(text(header, "alg"))) {
        throw new InvalidIssuanceException("holder proof must be ES256");
      }
      String message = new String(Base64URL.from(parts[1]).decode(), StandardCharsets.UTF_8);
      if (!MessageDigest.isEqual(
          message.getBytes(StandardCharsets.UTF_8),
          expectedMessage.getBytes(StandardCharsets.UTF_8))) {
        throw new InvalidIssuanceException("holder proof does not match this request");
      }
      Signature signature = Signature.getInstance("SHA256withECDSA");
      signature.initVerify(holderKey);
      signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
      byte[] der = ECDSA.transcodeSignatureToDER(Base64URL.from(parts[2]).decode());
      if (!signature.verify(der)) {
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

  /** Public federation metadata: verification keys of authorized issuers. */
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
                                      && !issuer.validThrough().isBefore(now))
                          .map(dev.sovra.trust.TrustService.IssuerView::publicKeyJwk)
                          .toList())
              .orElse(List.of());
      return mapper.writeValueAsString(Map.of("keys", keys));
    } catch (JacksonException e) {
      throw new IllegalStateException(e);
    }
  }
}
