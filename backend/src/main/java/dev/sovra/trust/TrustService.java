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
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Versioned trust registry (SOV-008). Snapshots are INSERT-only; activation
 * moves forward through a two-person approved proposal. Every mutation is
 * authorized, audited, and atomic with its evidence.
 */
@Service
public class TrustService {

  private final AuthorizationService authz;
  private final AuditService audit;
  private final JdbcTemplate global;
  private final Clock clock;
  private final ObjectMapper mapper;

  public TrustService(
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

  @Transactional
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
    GeneratedKeyHolder keys = new GeneratedKeyHolder();
    global.update(
        con -> {
          var ps = con.prepareStatement(
              "INSERT INTO trust_snapshot (created_by, note) VALUES (?, ?)",
              new String[] {"version"});
          ps.setString(1, maker.name());
          ps.setString(2, note == null ? "" : note);
          return ps;
        },
        keys);
    long version = keys.getKeyAs(Long.class);
    for (IssuerInput issuer : input.issuers()) {
      global.update(
          "INSERT INTO issuer_record (snapshot_version, issuer_id, display_name, scope,"
              + " credential_types, key_id, key_version, public_key_jwk, valid_from,"
              + " valid_through, status)"
              + " VALUES (?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?)",
          version,
          issuer.issuerId(),
          issuer.displayName(),
          issuer.scope(),
          issuer.credentialTypes().toArray(new String[0]),
          issuer.keyId(),
          issuer.keyVersion(),
          issuer.publicKeyJwk().toString(),
          java.sql.Timestamp.from(issuer.validFrom()),
          java.sql.Timestamp.from(issuer.validThrough()),
          issuer.status());
    }
    for (PolicyInput policy : input.policies()) {
      global.update(
          "INSERT INTO rp_policy (snapshot_version, rp_id, purpose, allowed_types, max_assurance)"
              + " VALUES (?, ?, ?, ?, ?)",
          version,
          policy.rpId(),
          policy.purpose(),
          policy.allowedTypes().toArray(new String[0]),
          policy.maxAssurance());
    }
    UUID proposalId = UUID.randomUUID();
    global.update(
        "INSERT INTO trust_change_proposal (id, snapshot_version, proposed_by) VALUES (?, ?, ?)",
        proposalId,
        version,
        maker.name());
    audit.record(
        maker,
        Action.PROPOSE_TRUST_CHANGE,
        ResourceRef.global("trust-snapshot", String.valueOf(version)),
        decision,
        "",
        Map.of("proposal", proposalId.toString(), "issuers", String.valueOf(input.issuers().size())));
    return new ProposalResult(version, proposalId);
  }

  @Transactional
  public void approve(ServiceAccountPrincipal checker, UUID proposalId) {
    ResourceRef resource = ResourceRef.global("trust-proposal", proposalId.toString());
    Decision decision =
        authz.authorize(Optional.of(checker), Action.APPROVE_TRUST_CHANGE, resource);
    if (!decision.permitted()) {
      audit.recordDenial(
          checker, Action.APPROVE_TRUST_CHANGE, resource, decision.reasonCode(),
          decision.policyVersion());
      throw new ForbiddenException(decision.reasonCode());
    }
    List<String> makers =
        global.query(
            "SELECT proposed_by FROM trust_change_proposal WHERE id = ?",
            (rs, row) -> rs.getString(1),
            proposalId);
    if (makers.isEmpty()) {
      throw new ProposalNotFoundException();
    }
    if (makers.get(0).equals(checker.name())) {
      audit.recordDenial(
          checker, Action.APPROVE_TRUST_CHANGE, resource, ReasonCode.SELF_APPROVAL,
          decision.policyVersion());
      throw new ForbiddenException(ReasonCode.SELF_APPROVAL);
    }
    try {
      global.update(
          "INSERT INTO trust_proposal_decision (proposal_id, approved_by) VALUES (?, ?)",
          proposalId,
          checker.name());
    } catch (DuplicateKeyException e) {
      throw new AlreadyDecidedException();
    }
    audit.record(
        checker, Action.APPROVE_TRUST_CHANGE, resource, decision, "", Map.of());
  }

  @Transactional
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
    global.update(
        "INSERT INTO trust_snapshot_activation (snapshot_version, activated_by) VALUES (?, ?)",
        version,
        activator.name());
    audit.record(
        activator, Action.ACTIVATE_TRUST_SNAPSHOT, resource, decision, "", Map.of());
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
