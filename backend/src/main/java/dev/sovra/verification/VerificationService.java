package dev.sovra.verification;

import dev.sovra.audit.AuditService;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ResourceRef;
import dev.sovra.crypto.HolderProofException;
import dev.sovra.crypto.HolderProofs;
import dev.sovra.issuance.LocalDevSigner;
import dev.sovra.issuance.StatusEvidenceFetcher;
import dev.sovra.issuance.TrustSnapshotProvider;
import dev.sovra.trust.TrustService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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
 * Durable multi-instance verification (SOV-011) over the SOV-010
 * consent-bound flow. A submission binds one proof request, one fresh
 * verifier nonce, the session audience, and a holder-signed binding
 * proof; the service checks signature, issuer/key scope, type/claims,
 * holder, time, status, audience, consent, and challenge (FR-08) plus
 * the session bindings (FR-19) before acceptance.
 *
 * <p>Every well-formed submission commits exactly one immutable
 * decision row — ACCEPTED, REJECTED, or UNKNOWN — together with its
 * audit row in a single transaction (INV-02). The database unique
 * constraint on (tenant, request, nonce) is the atomic nonce
 * consumption: across any number of instances the first INSERT wins
 * and every loser reconciles against the stored row, so a challenge
 * authorizes at most one fresh acceptance (INV-01) and idempotent
 * retries never mint another (INV-08). The same nonce replays the
 * stored response byte-for-byte; a fresh nonce permits a new attempt.
 * Follow-ups, including manual review, are separate records: nothing
 * rewrites a stored decision (FR-31).
 *
 * <p>Dependency failure or an uncertain outcome never returns a new
 * verified decision (INV-07, FR-12): a missing trust snapshot or a
 * status-dependency failure records UNKNOWN with a safe reason code,
 * and unexpected persistence failures propagate instead of inventing
 * an outcome.
 *
 * <p>G1 synthetic profile only: only artifacts labelled synthetic
 * verify here. The interoperable SD-JWT VC/OpenID4VP gate stays
 * closed until SOV-036 qualifies a profile.
 */
@Service
public class VerificationService {

  public static final String PROFILE = "sovra-g1-synthetic/0.2";
  static final String PRESENTATION_LABEL = "sovra-presentation/v1";
  static final String OUTCOME_ACCEPTED = "ACCEPTED";
  static final String OUTCOME_REJECTED = "REJECTED";
  static final String OUTCOME_UNKNOWN = "UNKNOWN";

  private final AuthorizationService authz;
  private final AuditService audit;
  private final TrustSnapshotProvider snapshots;
  private final StatusEvidenceFetcher status;
  private final JdbcTemplate tenant;
  private final Clock clock;
  private final ObjectMapper mapper;

  public VerificationService(
      AuthorizationService authz,
      AuditService audit,
      TrustSnapshotProvider snapshots,
      StatusEvidenceFetcher status,
      JdbcTemplate tenantJdbcTemplate,
      Clock clock,
      ObjectMapper mapper) {
    this.authz = authz;
    this.audit = audit;
    this.snapshots = snapshots;
    this.status = status;
    this.tenant = tenantJdbcTemplate;
    this.clock = clock;
    this.mapper = mapper;
  }

  public record VerifyRequest(
      UUID requestId, String nonce, String audience, JsonNode holderJwk, String bindingProof) {}

  public record DecisionView(
      UUID decisionId,
      UUID requestId,
      String outcome,
      String reasonCode,
      boolean synthetic,
      String profile,
      long trustSnapshot,
      Instant decidedAt) {}

  /**
   * Evaluates a presentation and returns the exact response body to
   * send. Replays are byte-identical to the original by construction.
   */
  @Transactional
  public String verify(ServiceAccountPrincipal caller, VerifyRequest request) {
    ResourceRef resource =
        ResourceRef.tenantScoped("verification", "presentations", caller.tenantId());
    Decision decision = authz.authorize(Optional.of(caller), Action.VERIFY_PRESENTATION, resource);
    if (!decision.permitted()) {
      audit.recordDenial(caller, Action.VERIFY_PRESENTATION, resource, decision.reasonCode(),
          decision.policyVersion());
      throw new ForbiddenException(decision.reasonCode());
    }
    Validated validated = validate(request);
    StoredRequest stored = loadRequest(caller, request.requestId());
    Credential credential = loadCredential(stored.credentialId());

    Optional<String> replay =
        checkReplay(caller, decision, request, validated.hash());
    if (replay.isPresent()) {
      return replay.get();
    }

    Evaluated evaluated = evaluate(request, stored, credential);
    Instant now = clock.instant();
    UUID decisionId = UUID.randomUUID();
    String response =
        responseBody(decisionId, request.requestId(), evaluated, now);
    // A savepoint around the contested INSERT: PostgreSQL aborts the
    // whole transaction on a unique violation, so the loser rolls back
    // to the savepoint before reconciling against the winner's row.
    // The savepoint rides the transaction-bound connection, so this
    // works for container-managed and programmatic transactions alike.
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
          "INSERT INTO verification_decision (id, tenant_id, request_id, credential_id, nonce,"
              + " request_hash, rp_id, audience, outcome, reason_code, response_body,"
              + " trust_snapshot_version, decided_at, decided_by)"
              + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
          decisionId, caller.tenantId(), request.requestId(), stored.credentialId(),
          request.nonce(), validated.hash(), stored.rpId(), request.audience(),
          evaluated.outcome(), evaluated.reason(), response, evaluated.snapshot(),
          java.sql.Timestamp.from(now), caller.name());
      connection.releaseSavepoint(savepoint);
    } catch (DuplicateKeyException e) {
      // Lost a race with the same nonce: reconcile against durable state.
      try {
        connection.rollback(savepoint);
      } catch (java.sql.SQLException rollback) {
        throw new IllegalStateException("savepoint rollback failed", rollback);
      }
      return checkReplay(caller, decision, request, validated.hash())
          .orElseThrow(() -> new IllegalStateException("decision record vanished"));
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
    audit.record(caller, Action.VERIFY_PRESENTATION,
        ResourceRef.tenantScoped("verification", decisionId.toString(), caller.tenantId()),
        decision, "",
        detail(decisionId, request.requestId(), evaluated));
    return response;
  }

  /** Authorized retrieval of an already committed decision. */
  public DecisionView get(ServiceAccountPrincipal caller, UUID decisionId) {
    ResourceRef resource =
        ResourceRef.tenantScoped("verification", decisionId.toString(), caller.tenantId());
    Decision decision = authz.authorize(Optional.of(caller), Action.READ_VERIFICATION, resource);
    if (!decision.permitted()) {
      audit.recordDenial(caller, Action.READ_VERIFICATION, resource, decision.reasonCode(),
          decision.policyVersion());
      throw new ForbiddenException(decision.reasonCode());
    }
    List<DecisionView> rows =
        tenant.query(
            "SELECT id, request_id, outcome, reason_code, trust_snapshot_version, decided_at"
                + " FROM verification_decision WHERE id = ? AND tenant_id = ?",
            (rs, row) ->
                new DecisionView(
                    rs.getObject("id", UUID.class),
                    rs.getObject("request_id", UUID.class),
                    rs.getString("outcome"),
                    rs.getString("reason_code"),
                    true,
                    PROFILE,
                    rs.getLong("trust_snapshot_version"),
                    rs.getTimestamp("decided_at").toInstant()),
            decisionId,
            caller.tenantId());
    if (rows.isEmpty()) {
      throw new VerificationNotFoundException();
    }
    DecisionView view = rows.get(0);
    audit.record(caller, Action.READ_VERIFICATION, resource, decision, "",
        Map.of("decision", decisionId.toString(), "outcome", view.outcome()));
    return view;
  }

  /**
   * Canonical presentation message. The holder binds this verification
   * attempt — request, fresh nonce, session audience — to the holder
   * the credential names. Changing any bound element breaks the proof.
   */
  static String presentationMessage(
      UUID requestId, String nonce, String audience, String holderThumbprint) {
    return PRESENTATION_LABEL + "\n" + requestId + "\n" + nonce + "\n" + audience + "\n"
        + holderThumbprint;
  }

  private record Validated(String hash) {}

  private record StoredRequest(
      UUID credentialId,
      String rpId,
      String audience,
      String purpose,
      String state,
      Instant expiresAt,
      String consentArtifact) {}

  private record Credential(
      UUID id, String issuerId, String vct, String holderThumbprint, Instant expiresAt,
      String artifact) {}

  private record Evaluated(String outcome, String reason, long snapshot) {}

  private record DecisionRow(String requestHash, String responseBody) {}

  private Optional<String> checkReplay(
      ServiceAccountPrincipal caller, Decision decision, VerifyRequest request, String hash) {
    List<DecisionRow> rows =
        tenant.query(
            "SELECT request_hash, response_body FROM verification_decision"
                + " WHERE tenant_id = ? AND request_id = ? AND nonce = ?",
            (rs, row) -> new DecisionRow(rs.getString(1), rs.getString(2)),
            caller.tenantId(), request.requestId(), request.nonce());
    if (rows.isEmpty()) {
      return Optional.empty();
    }
    DecisionRow row = rows.get(0);
    if (!row.requestHash().equals(hash)) {
      // Same nonce, different content: the stored decision stands and
      // this submission decides nothing.
      throw new VerificationConflictException();
    }
    audit.record(
        caller, Action.VERIFY_PRESENTATION,
        ResourceRef.tenantScoped(
            "verification", request.requestId().toString(), caller.tenantId()),
        decision, "", Map.of("request", request.requestId().toString(), "replay", "true"));
    return Optional.of(row.responseBody());
  }

  /**
   * Runs every check in dependency order: durable local truth
   * (consent, credential time) first, then live dependencies whose
   * outage yields UNKNOWN, then trust and proof checks. Only a clean
   * run accepts.
   */
  private Evaluated evaluate(VerifyRequest request, StoredRequest stored, Credential credential) {
    Instant now = clock.instant();
    if (!"APPROVED".equals(stored.state()) || stored.consentArtifact() == null) {
      return new Evaluated(OUTCOME_REJECTED, "CONSENT_NOT_APPROVED", 0);
    }
    if (!stored.expiresAt().isAfter(now)) {
      return new Evaluated(OUTCOME_REJECTED, "CONSENT_EXPIRED", 0);
    }
    if (!credential.expiresAt().isAfter(now)) {
      return new Evaluated(OUTCOME_REJECTED, "CREDENTIAL_EXPIRED", 0);
    }
    StatusEvidenceFetcher.StatusEvidence evidence = fetchStatus(credential.id());
    if (evidence == null) {
      return new Evaluated(OUTCOME_UNKNOWN, "STATUS_UNAVAILABLE", 0);
    }
    if (evidence.status() == StatusEvidenceFetcher.Status.REVOKED) {
      return new Evaluated(OUTCOME_REJECTED, "CREDENTIAL_REVOKED", 0);
    }
    if (evidence.status() == StatusEvidenceFetcher.Status.UNKNOWN) {
      return new Evaluated(OUTCOME_UNKNOWN, "STATUS_UNKNOWN", 0);
    }
    Optional<TrustService.SnapshotView> current = snapshots.current();
    if (current.isEmpty()) {
      return new Evaluated(OUTCOME_UNKNOWN, "TRUST_UNAVAILABLE", 0);
    }
    TrustService.SnapshotView snapshot = current.get();
    try {
      SyntheticArtifactVerifier.verify(
          credential.artifact(),
          new SyntheticArtifactVerifier.Expected(
              credential.issuerId(), credential.vct(), credential.holderThumbprint(),
              credential.id(), credential.expiresAt()),
          snapshot, tenant, mapper, now);
    } catch (SyntheticArtifactVerifier.ArtifactFailure e) {
      return new Evaluated(OUTCOME_REJECTED, e.reason(), snapshot.version());
    }
    if (!policyAllows(snapshot, stored, credential)) {
      return new Evaluated(OUTCOME_REJECTED, "POLICY_DENIED", snapshot.version());
    }
    ECPublicKey holderKey;
    try {
      holderKey = HolderProofs.parseP256Key(request.holderJwk());
    } catch (HolderProofException e) {
      return new Evaluated(OUTCOME_REJECTED, "HOLDER_KEY_INVALID", snapshot.version());
    }
    String thumbprint = LocalDevSigner.thumbprint(
        holderKey.getW().getAffineX(), holderKey.getW().getAffineY());
    if (!credential.holderThumbprint().equals(thumbprint)) {
      return new Evaluated(OUTCOME_REJECTED, "HOLDER_MISMATCH", snapshot.version());
    }
    if (!stored.audience().equals(request.audience())) {
      return new Evaluated(OUTCOME_REJECTED, "AUDIENCE_MISMATCH", snapshot.version());
    }
    try {
      HolderProofs.verifyEs256(
          holderKey,
          request.bindingProof(),
          presentationMessage(
              request.requestId(), request.nonce(), request.audience(), thumbprint),
          mapper);
    } catch (HolderProofException e) {
      return new Evaluated(OUTCOME_REJECTED, "BINDING_INVALID", snapshot.version());
    }
    return new Evaluated(OUTCOME_ACCEPTED, "OK", snapshot.version());
  }

  /**
   * RP policy check. Snapshots that carry no RP policies (including the
   * G1 genesis snapshot) skip this gate; snapshots that do must name
   * the RP, purpose, and credential type explicitly.
   */
  private static boolean policyAllows(
      TrustService.SnapshotView snapshot, StoredRequest stored, Credential credential) {
    if (snapshot.policies().isEmpty()) {
      return true;
    }
    return snapshot.policies().stream()
        .anyMatch(
            policy ->
                stored.rpId().equals(policy.rpId())
                    && stored.purpose().equals(policy.purpose())
                    && policy.allowedTypes().contains(credential.vct()));
  }

  /** A status-dependency failure is UNKNOWN, never an acceptance. */
  private StatusEvidenceFetcher.StatusEvidence fetchStatus(UUID credentialId) {
    try {
      return status.fetch(credentialId);
    } catch (RuntimeException e) {
      return null;
    }
  }

  private Validated validate(VerifyRequest request) {
    if (request == null
        || request.requestId() == null
        || request.nonce() == null
        || request.audience() == null
        || request.holderJwk() == null
        || request.bindingProof() == null
        || request.bindingProof().isBlank()) {
      throw new InvalidVerificationException("verification submission is incomplete");
    }
    if (!request.nonce().matches("[A-Za-z0-9_-]{16,128}")) {
      throw new InvalidVerificationException("nonce is malformed");
    }
    if (request.audience().isBlank() || request.audience().length() > 256) {
      throw new InvalidVerificationException("audience is malformed");
    }
    return new Validated(requestHash(request));
  }

  private String requestHash(VerifyRequest request) {
    String jwk;
    try {
      jwk = mapper.writeValueAsString(request.holderJwk());
    } catch (JacksonException e) {
      jwk = String.valueOf(request.holderJwk());
    }
    String canonical = request.requestId() + "\n" + request.nonce() + "\n" + request.audience()
        + "\n" + jwk + "\n" + request.bindingProof();
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private StoredRequest loadRequest(ServiceAccountPrincipal caller, UUID requestId) {
    List<StoredRequest> rows =
        tenant.query(
            "SELECT credential_id, rp_id, audience, purpose, state, expires_at, consent_artifact"
                + " FROM proof_request WHERE id = ? AND tenant_id = ?",
            (rs, row) ->
                new StoredRequest(
                    rs.getObject("credential_id", UUID.class),
                    rs.getString("rp_id"),
                    rs.getString("audience"),
                    rs.getString("purpose"),
                    rs.getString("state"),
                    rs.getTimestamp("expires_at").toInstant(),
                    rs.getString("consent_artifact")),
            requestId,
            caller.tenantId());
    if (rows.isEmpty()) {
      throw new VerificationNotFoundException();
    }
    return rows.get(0);
  }

  private Credential loadCredential(UUID credentialId) {
    List<Credential> rows =
        tenant.query(
            "SELECT id, issuer_id, vct, holder_thumbprint, expires_at, artifact"
                + " FROM credential_artifact WHERE id = ?",
            (rs, row) ->
                new Credential(
                    rs.getObject("id", UUID.class),
                    rs.getString("issuer_id"),
                    rs.getString("vct"),
                    rs.getString("holder_thumbprint"),
                    rs.getTimestamp("expires_at").toInstant(),
                    rs.getString("artifact")),
            credentialId);
    if (rows.isEmpty()) {
      throw new VerificationNotFoundException();
    }
    return rows.get(0);
  }

  private String responseBody(
      UUID decisionId, UUID requestId, Evaluated evaluated, Instant decidedAt) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("decisionId", decisionId.toString());
    body.put("requestId", requestId.toString());
    body.put("outcome", evaluated.outcome());
    body.put("reasonCode", evaluated.reason());
    body.put("synthetic", Boolean.TRUE);
    body.put("profile", PROFILE);
    body.put("trustSnapshot", evaluated.snapshot());
    body.put("decidedAt", decidedAt.toString());
    try {
      return mapper.writeValueAsString(body);
    } catch (JacksonException e) {
      throw new IllegalStateException(e);
    }
  }

  private Map<String, String> detail(UUID decisionId, UUID requestId, Evaluated evaluated) {
    Map<String, String> detail = new LinkedHashMap<>();
    detail.put("decision", decisionId.toString());
    detail.put("request", requestId.toString());
    detail.put("outcome", evaluated.outcome());
    detail.put("reason", evaluated.reason());
    detail.put("snapshot", String.valueOf(evaluated.snapshot()));
    return detail;
  }
}
