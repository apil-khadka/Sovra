package dev.sovra.trust;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import dev.sovra.audit.AuditService;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.authz.ResourceRef;
import dev.sovra.config.SovraMode;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Versioned trust registry (SOV-008, sealed by SOV-040). The runtime role
 * holds SELECT only on trust tables: every mutation goes through the
 * SECURITY DEFINER functions (V13), which enforce fresh versions, linked
 * proposals, UUID-distinct maker/checker, and lawful activation. Activated
 * versions are immutable for every role, including the migration owner.
 * Approval identity is the authenticated account UUID — display names are
 * labels only — with optional human binding (OIDC subject + AMR) recorded
 * for BFF-session callers; production additionally requires a
 * person-verified quorum and refuses synthetic snapshots.
 */
@Service
public class TrustService {

  private final AuthorizationService authz;
  private final AuditService audit;
  private final JdbcTemplate global;
  private final Clock clock;
  private final ObjectMapper mapper;
  private final SovraMode mode;

  public TrustService(
      AuthorizationService authz,
      AuditService audit,
      DataSource globalDataSource,
      Clock clock,
      ObjectMapper mapper,
      SovraMode mode) {
    this.authz = authz;
    this.audit = audit;
    this.global = new JdbcTemplate(globalDataSource);
    this.clock = clock;
    this.mapper = mapper;
    this.mode = mode;
  }

  /** Public federation metadata; no authentication required. */
  public Optional<SnapshotView> currentSnapshot() {
    List<Long> active =
        global.query(
            "SELECT snapshot_version FROM trust_snapshot_activation ORDER BY snapshot_version DESC LIMIT 1",
            (rs, row) -> rs.getLong(1));
    if (active.isEmpty()) {
      return Optional.empty();
    }
    long version = active.get(0);
    List<IssuerView> issuers =
        global.query(
            "SELECT issuer_id, display_name, scope, credential_types, key_id, key_version,"
                + " public_key_jwk, valid_from, valid_through, status"
                + " FROM issuer_record WHERE snapshot_version = ?",
            (rs, row) ->
                new IssuerView(
                    rs.getString("issuer_id"),
                    rs.getString("display_name"),
                    rs.getString("scope"),
                    List.of((String[]) rs.getArray("credential_types").getArray()),
                    rs.getString("key_id"),
                    rs.getInt("key_version"),
                    readTree(rs.getString("public_key_jwk")),
                    rs.getTimestamp("valid_from").toInstant(),
                    rs.getTimestamp("valid_through").toInstant(),
                    rs.getString("status")),
            version);
    List<PolicyView> policies =
        global.query(
            "SELECT rp_id, purpose, allowed_types, max_assurance FROM rp_policy"
                + " WHERE snapshot_version = ?",
            (rs, row) ->
                new PolicyView(
                    rs.getString("rp_id"),
                    rs.getString("purpose"),
                    List.of((String[]) rs.getArray("allowed_types").getArray()),
                    rs.getString("max_assurance")),
            version);
    return Optional.of(new SnapshotView(version, issuers, policies));
  }

  private JsonNode readTree(String json) {
    try {
      return mapper.readTree(json);
    } catch (tools.jackson.core.JacksonException e) {
      throw new IllegalStateException("stored JWK is not JSON", e);
    }
  }

  /**
   * Immutable approval identity. Machine callers bind their account UUID;
   * BFF-session callers additionally bind OIDC subject + AMR. Display
   * names travel as labels only and no rule compares them.
   */
  public record ApprovalIdentity(
      UUID accountId, String displayName, String subject, List<String> amr) {
    /**
     * Identity the quorum rules see. Humans bind their OIDC subject;
     * machines bind only their account. AMR stays empty until a BFF
     * trust endpoint can pass the session's authentication methods
     * through (SOV-040 gap); the subject alone already separates two
     * people from one person with two accounts.
     */
    public static ApprovalIdentity of(ServiceAccountPrincipal caller) {
      return new ApprovalIdentity(caller.id(), caller.name(), caller.subject(), List.of());
    }
  }

  private record Maker(UUID accountId, String subject) {}

  // Denials must survive as evidence: every ForbiddenException below is
  // thrown before any business write, so committing the denial audit is
  // safe (the production quorum refusal is pre-computed for this reason).
  @Transactional(noRollbackFor = ForbiddenException.class)
  public ProposalResult propose(ServiceAccountPrincipal maker, ProposalInput input, String note) {
    ResourceRef resource = ResourceRef.global("trust-registry", "proposals");
    Decision decision =
        authz.authorize(Optional.of(maker), Action.PROPOSE_TRUST_CHANGE, resource);
    if (!decision.permitted()) {
      audit.recordDenial(
          maker, Action.PROPOSE_TRUST_CHANGE, resource, decision.reasonCode(),
          decision.policyVersion());
      throw new ForbiddenException(decision.reasonCode());
    }
    TrustProposalValidator.validate(input, clock.instant());
    ApprovalIdentity identity = ApprovalIdentity.of(maker);
    try {
      Map<String, Object> row =
          global.queryForMap(
              "SELECT * FROM trust_propose(?, ?, ?, ?::text[], ?, ?::jsonb, ?::jsonb)",
              identity.accountId(),
              identity.displayName(),
              identity.subject(),
              identity.amr().isEmpty() ? null : identity.amr().toArray(new String[0]),
              note == null ? "" : note,
              issuersJson(input.issuers()),
              policiesJson(input.policies()));
      long version = ((Number) row.get("version")).longValue();
      UUID proposalId = (UUID) row.get("proposal_id");
      audit.record(
          maker,
          Action.PROPOSE_TRUST_CHANGE,
          ResourceRef.global("trust-snapshot", String.valueOf(version)),
          decision,
          "",
          Map.of(
              "proposal",
              proposalId.toString(),
              "issuers",
              String.valueOf(input.issuers().size())));
      return new ProposalResult(version, proposalId);
    } catch (DataAccessException e) {
      throw trustFunctionError(e);
    }
  }

  /**
   * Records the checker's approval. Returns whether the quorum is
   * person-verified (both sides human-bound to distinct person
   * identities); production refuses quorums that are not.
   */
  @Transactional(noRollbackFor = ForbiddenException.class)
  public boolean approve(ServiceAccountPrincipal checker, UUID proposalId) {
    ResourceRef resource = ResourceRef.global("trust-proposal", proposalId.toString());
    Decision decision =
        authz.authorize(Optional.of(checker), Action.APPROVE_TRUST_CHANGE, resource);
    if (!decision.permitted()) {
      audit.recordDenial(
          checker, Action.APPROVE_TRUST_CHANGE, resource, decision.reasonCode(),
          decision.policyVersion());
      throw new ForbiddenException(decision.reasonCode());
    }
    if (alreadyDecided(proposalId)) {
      throw new AlreadyDecidedException();
    }
    Maker maker = makerOf(proposalId);
    if (maker == null) {
      throw new ProposalNotFoundException();
    }
    if (maker.accountId() == null) {
      // Migration-seed proposals carry no maker identity and are decided
      // by the seed itself; anything else reaching here is corrupt.
      throw new InvalidProposalException("proposal has no recorded maker");
    }
    if (maker.accountId().equals(checker.id())) {
      denySelfApproval(checker, resource, decision);
      throw new ForbiddenException(ReasonCode.SELF_APPROVAL);
    }
    // Same-person (distinct accounts, one OIDC subject) is enforced
    // inside trust_approve, which sees both sides' human binding.
    // Machine callers carry no subject; BFF-session humans do.
    // The production quorum verdict is pre-computed with the same rule
    // so the refusal lands before any business write.
    boolean quorum =
        maker.subject() != null && checkerSubject(checker) != null
            && !maker.subject().equals(checkerSubject(checker));
    if (mode.isProduction() && !quorum) {
      audit.recordDenial(
          checker, Action.APPROVE_TRUST_CHANGE, resource,
          ReasonCode.ASSURANCE_INSUFFICIENT, decision.policyVersion());
      throw new ForbiddenException(ReasonCode.ASSURANCE_INSUFFICIENT);
    }
    boolean verified;
    try {
      Boolean result =
          global.queryForObject(
              "SELECT trust_approve(?, ?, ?, ?, ?::text[])",
              Boolean.class,
              proposalId,
              checker.id(),
              checker.name(),
              checkerSubject(checker),
              null);
      verified = Boolean.TRUE.equals(result);
    } catch (DataAccessException e) {
      throw trustFunctionError(e);
    }
    Map<String, String> detail = new LinkedHashMap<>();
    detail.put("person_verified", String.valueOf(verified));
    audit.record(checker, Action.APPROVE_TRUST_CHANGE, resource, decision, "", detail);
    return verified;
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public void activate(ServiceAccountPrincipal activator, long version) {
    ResourceRef resource = ResourceRef.global("trust-snapshot", String.valueOf(version));
    Decision decision =
        authz.authorize(Optional.of(activator), Action.ACTIVATE_TRUST_SNAPSHOT, resource);
    if (!decision.permitted()) {
      audit.recordDenial(
          activator, Action.ACTIVATE_TRUST_SNAPSHOT, resource, decision.reasonCode(),
          decision.policyVersion());
      throw new ForbiddenException(decision.reasonCode());
    }
    List<Long> approved =
        global.query(
            "SELECT p.snapshot_version FROM trust_change_proposal p"
                + " JOIN trust_proposal_decision d ON d.proposal_id = p.id"
                + " WHERE p.snapshot_version = ?",
            (rs, row) -> rs.getLong(1),
            version);
    if (approved.isEmpty()) {
      throw new InvalidProposalException("version has no approved proposal");
    }
    Long current =
        global.queryForObject(
            "SELECT COALESCE(MAX(snapshot_version), 0) FROM trust_snapshot_activation",
            Long.class);
    if (current != null && version <= current) {
      throw new InvalidProposalException("activation only moves forward");
    }
    if (mode.isProduction() && snapshotIsSynthetic(version)) {
      throw new InvalidProposalException("synthetic snapshot cannot activate in production");
    }
    try {
      global.queryForMap(
          "SELECT trust_activate(?, ?, ?)",
          version,
          activator.id(),
          activator.name());
    } catch (DataAccessException e) {
      throw trustFunctionError(e);
    }
    audit.record(
        activator, Action.ACTIVATE_TRUST_SNAPSHOT, resource, decision, "", Map.of());
  }

  /** OIDC subject binding the principal carried in; null for machines. */
  private static String checkerSubject(ServiceAccountPrincipal checker) {
    return checker.subject();
  }

  private Maker makerOf(UUID proposalId) {
    List<Maker> makers =
        global.query(
            "SELECT proposed_by_account, proposed_by_subject FROM trust_change_proposal WHERE id = ?",
            (rs, row) -> new Maker(rs.getObject(1, UUID.class), rs.getString(2)),
            proposalId);
    return makers.isEmpty() ? null : makers.get(0);
  }

  private boolean alreadyDecided(UUID proposalId) {
    Integer count =
        global.queryForObject(
            "SELECT COUNT(*) FROM trust_proposal_decision WHERE proposal_id = ?",
            Integer.class,
            proposalId);
    return count != null && count > 0;
  }

  private void denySelfApproval(
      ServiceAccountPrincipal checker, ResourceRef resource, Decision decision) {
    audit.recordDenial(
        checker, Action.APPROVE_TRUST_CHANGE, resource, ReasonCode.SELF_APPROVAL,
        decision.policyVersion());
  }

  /** Synthetic markers (SOV-040): example issuers and the synthetic scope. */
  private boolean snapshotIsSynthetic(long version) {
    Integer count =
        global.queryForObject(
            "SELECT COUNT(*) FROM issuer_record"
                + " WHERE snapshot_version = ?"
                + " AND (scope = 'synthetic-only' OR issuer_id LIKE 'https://sovra.example/%')",
            Integer.class,
            version);
    return count != null && count > 0;
  }

  /**
   * Maps seal-function rejections (race backstops behind the Java
   * pre-checks) to domain errors. Unknown database failures propagate.
   */
  private RuntimeException trustFunctionError(DataAccessException e) {
    String message = String.valueOf(e.getMessage());
    if (message.contains("already decided")) {
      return new AlreadyDecidedException();
    }
    if (message.contains("unknown proposal")) {
      return new ProposalNotFoundException();
    }
    if (message.contains("self-approval") || message.contains("one person identity")) {
      return new ForbiddenException(ReasonCode.SELF_APPROVAL);
    }
    if (message.contains("refused")) {
      return new InvalidProposalException("trust write refused");
    }
    return e;
  }

  private String issuersJson(List<IssuerInput> issuers) {
    List<Map<String, Object>> rows = new ArrayList<>();
    for (IssuerInput issuer : issuers) {
      Map<String, Object> row = new LinkedHashMap<>();
      row.put("issuer_id", issuer.issuerId());
      row.put("display_name", issuer.displayName());
      row.put("scope", issuer.scope());
      row.put("credential_types", issuer.credentialTypes());
      row.put("key_id", issuer.keyId());
      row.put("key_version", issuer.keyVersion());
      row.put("public_key_jwk", issuer.publicKeyJwk());
      row.put("valid_from", issuer.validFrom().toString());
      row.put("valid_through", issuer.validThrough().toString());
      row.put("status", issuer.status());
      rows.add(row);
    }
    return toJson(rows);
  }

  private String policiesJson(List<PolicyInput> policies) {
    List<Map<String, Object>> rows = new ArrayList<>();
    for (PolicyInput policy : policies) {
      Map<String, Object> row = new LinkedHashMap<>();
      row.put("rp_id", policy.rpId());
      row.put("purpose", policy.purpose());
      row.put("allowed_types", policy.allowedTypes());
      row.put("max_assurance", policy.maxAssurance());
      rows.add(row);
    }
    return toJson(rows);
  }

  private String toJson(Object value) {
    try {
      return mapper.writeValueAsString(value);
    } catch (tools.jackson.core.JacksonException e) {
      throw new IllegalStateException("trust proposal is not JSON", e);
    }
  }

  public record ProposalInput(List<IssuerInput> issuers, List<PolicyInput> policies) {}

  public record IssuerInput(
      String issuerId,
      String displayName,
      String scope,
      List<String> credentialTypes,
      String keyId,
      int keyVersion,
      JsonNode publicKeyJwk,
      Instant validFrom,
      Instant validThrough,
      String status) {}

  public record PolicyInput(
      String rpId, String purpose, List<String> allowedTypes, String maxAssurance) {}

  public record ProposalResult(long version, UUID proposalId) {}

  public record SnapshotView(long version, List<IssuerView> issuers, List<PolicyView> policies) {}

  public record IssuerView(
      String issuerId,
      String displayName,
      String scope,
      List<String> credentialTypes,
      String keyId,
      int keyVersion,
      JsonNode publicKeyJwk,
      Instant validFrom,
      Instant validThrough,
      String status) {}

  public record PolicyView(String rpId, String purpose, List<String> allowedTypes,
      String maxAssurance) {}
}
