package dev.sovra.consent;

import dev.sovra.audit.AuditService;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ResourceRef;
import dev.sovra.crypto.HolderProofException;
import dev.sovra.crypto.HolderProofs;
import dev.sovra.guard.CandidatePlan;
import dev.sovra.guard.GuardRejectedException;
import dev.sovra.guard.GuardService;
import dev.sovra.guard.PlanGuard;
import dev.sovra.guard.PlanParser;
import dev.sovra.guard.SelectedPolicy;
import dev.sovra.crypto.P256;
import dev.sovra.trust.TrustSnapshotProvider;
import dev.sovra.issuance.TrustUnavailableException;
import dev.sovra.ops.TelemetryService;
import dev.sovra.trust.AlreadyDecidedException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Consent-bound proof requests (SOV-010). An RP opens a request naming the
 * exact relying party, audience, purpose, claims, plan hash, challenge and
 * expiry; the holder reviews those exact values and signs an explicit
 * approve/deny decision with the credential's holder key. The stored
 * request is immutable, so any scope edit invalidates the consent proof
 * instead of widening it. Refusal, inactivity, a wrong holder, or an
 * expired consent or credential leaves no authorized presentation behind.
 *
 * <p>G1 synthetic profile only: claims stay on the SOV-001 allowlist and
 * every presentation is labelled synthetic. Transport authentication is a
 * tenant service account; holder authority comes from the key proof, never
 * from the caller's roles.
 *
 * <p>The deterministic plan guard (SOV-014) runs before any holder
 * request is created: the candidate plan must be guard-accepted and the
 * bound plan hash must equal the plan's canonical hash, so the wallet
 * reviews exactly the plan the guard approved.
 */
@Service
public class ConsentService {

  static final Duration MIN_LIFETIME = Duration.ofMinutes(1);
  static final Duration MAX_LIFETIME = Duration.ofHours(24);
  static final String CONSENT_LABEL = "sovra-consent/v1";
  static final String PROFILE = "sovra-g1-synthetic/0.2";
  static final String CLAIMS_CANONICAL = "adultOver18=true";
  static final String DECIDE_APPROVE = "approve";
  static final String DECIDE_DENY = "deny";

  private final AuthorizationService authz;
  private final AuditService audit;
  private final TrustSnapshotProvider snapshots;
  private final GuardService guard;
  private final JdbcTemplate tenant;
  private final Clock clock;
  private final ObjectMapper mapper;
  private final TelemetryService telemetry;

  public ConsentService(
      AuthorizationService authz,
      AuditService audit,
      TrustSnapshotProvider snapshots,
      GuardService guard,
      JdbcTemplate tenantJdbcTemplate,
      Clock clock,
      ObjectMapper mapper,
      TelemetryService telemetry) {
    this.authz = authz;
    this.audit = audit;
    this.snapshots = snapshots;
    this.guard = guard;
    this.tenant = tenantJdbcTemplate;
    this.clock = clock;
    this.mapper = mapper;
    this.telemetry = telemetry;
  }

  public record CreateRequest(
      String rpId,
      String audience,
      String purpose,
      UUID credentialId,
      Map<String, Object> claims,
      JsonNode plan,
      String policyId,
      String policyVersion,
      String planHash,
      String challenge,
      Instant expiresAt) {}

  public record DecisionRequest(String decision, JsonNode holderJwk, String consentProof) {}

  public record RequestView(
      UUID requestId,
      String rpId,
      String audience,
      String purpose,
      UUID credentialId,
      Map<String, Object> claims,
      String planHash,
      String challenge,
      String holderThumbprint,
      String state,
      String stateReason,
      Instant createdAt,
      Instant expiresAt,
      long trustSnapshot) {}

  public record PresentationView(
      UUID requestId,
      String state,
      boolean synthetic,
      String profile,
      String presentation,
      Map<String, Object> claims,
      Instant expiresAt,
      long trustSnapshot) {}

  /** Opens a proof request against a currently usable credential. */
  @Transactional
  public RequestView create(ServiceAccountPrincipal caller, CreateRequest request) {
    return telemetry.time(
        caller.tenantId(),
        TelemetryService.Stage.CONSENT_CREATE,
        Set.of(InvalidConsentException.class, TrustUnavailableException.class,
            GuardRejectedException.class),
        () -> createInner(caller, request));
  }

  private RequestView createInner(ServiceAccountPrincipal caller, CreateRequest request) {
    ResourceRef resource =
        ResourceRef.tenantScoped("proof-request", "requests", caller.tenantId());
    Decision decision = authz.authorize(Optional.of(caller), Action.REQUEST_PROOF, resource);
    if (!decision.permitted()) {
      audit.recordDenial(caller, Action.REQUEST_PROOF, resource, decision.reasonCode(),
          decision.policyVersion());
      throw new ForbiddenException(decision.reasonCode());
    }
    Instant now = clock.instant();
    Validated validated = validate(request, now);
    requireGuardAccepted(caller, request);
    var snapshot = snapshots.current().orElseThrow(TrustUnavailableException::new);

    UUID requestId = UUID.randomUUID();
    tenant.update(
        "INSERT INTO proof_request (id, tenant_id, credential_id, rp_id, audience, purpose,"
            + " claims, plan_hash, challenge, holder_thumbprint, state, created_at, expires_at,"
            + " trust_snapshot_version, created_by)"
            + " VALUES (?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, 'PENDING', ?, ?, ?, ?)",
        requestId, caller.tenantId(), request.credentialId(), request.rpId(),
        request.audience(), request.purpose(), validated.claimsJson(), request.planHash(),
        request.challenge(), validated.holderThumbprint(),
        java.sql.Timestamp.from(now), java.sql.Timestamp.from(request.expiresAt()),
        snapshot.version(), caller.name());
    audit.record(caller, Action.REQUEST_PROOF,
        ResourceRef.tenantScoped("proof-request", requestId.toString(), caller.tenantId()),
        decision, "",
        detail(requestId, request, validated.holderThumbprint(), snapshot.version()));
    return view(load(caller, requestId), now);
  }

  /** Holder review: the exact bound values plus the derived consent state. */
  public RequestView get(ServiceAccountPrincipal caller, UUID requestId) {
    ResourceRef resource =
        ResourceRef.tenantScoped("proof-request", requestId.toString(), caller.tenantId());
    Decision decision = authz.authorize(Optional.of(caller), Action.READ_CONSENT, resource);
    if (!decision.permitted()) {
      audit.recordDenial(caller, Action.READ_CONSENT, resource, decision.reasonCode(),
          decision.policyVersion());
      throw new ForbiddenException(decision.reasonCode());
    }
    return view(load(caller, requestId), clock.instant());
  }

  /**
   * Records the holder's explicit signed decision. The proof must cover the
   * stored request bytes exactly; anything the holder did not review —
   * edited scope, another holder, an expired request — fails closed.
   */
  @Transactional
  public RequestView decide(ServiceAccountPrincipal caller, UUID requestId, DecisionRequest input) {
    return telemetry.time(
        caller.tenantId(),
        TelemetryService.Stage.CONSENT_DECIDE,
        Set.of(InvalidConsentException.class, ConsentNotFoundException.class,
            AlreadyDecidedException.class, TrustUnavailableException.class,
            GuardRejectedException.class),
        () -> decideInner(caller, requestId, input));
  }

  private RequestView decideInner(
      ServiceAccountPrincipal caller, UUID requestId, DecisionRequest input) {
    ResourceRef resource =
        ResourceRef.tenantScoped("proof-request", requestId.toString(), caller.tenantId());
    Decision decision = authz.authorize(Optional.of(caller), Action.DECIDE_CONSENT, resource);
    if (!decision.permitted()) {
      audit.recordDenial(caller, Action.DECIDE_CONSENT, resource, decision.reasonCode(),
          decision.policyVersion());
      throw new ForbiddenException(decision.reasonCode());
    }
    Stored row = load(caller, requestId);
    if (!"PENDING".equals(row.state())) {
      throw new AlreadyDecidedException();
    }
    if (input == null
        || (!DECIDE_APPROVE.equals(input.decision()) && !DECIDE_DENY.equals(input.decision()))) {
      throw new InvalidConsentException("decision must be approve or deny");
    }
    Instant now = clock.instant();
    if (!row.expiresAt().isAfter(now)) {
      throw new InvalidConsentException("consent request has expired");
    }
    requireUsableCredential(row.credentialId());
    ECPublicKey holderKey = parseHolderKey(input.holderJwk());
    String thumbprint = P256.thumbprint(
        holderKey.getW().getAffineX(), holderKey.getW().getAffineY());
    if (!row.holderThumbprint().equals(thumbprint)) {
      throw new InvalidConsentException("consent proof is bound to another holder");
    }
    verifyConsentProof(holderKey, input.consentProof(), consentMessage(row, input.decision()));
    String state = DECIDE_APPROVE.equals(input.decision()) ? "APPROVED" : "DENIED";
    tenant.update(
        "UPDATE proof_request SET state = ?, decided_at = ?, consent_artifact = ?"
            + " WHERE id = ? AND tenant_id = ?",
        state, java.sql.Timestamp.from(now), input.consentProof(),
        requestId, caller.tenantId());
    audit.record(caller, Action.DECIDE_CONSENT, resource, decision, "",
        Map.of("request", requestId.toString(), "decision", input.decision()));
    return view(load(caller, requestId), now);
  }

  /**
   * Returns the authorized presentation only while consent is verified:
   * approved, unexpired, and backed by a still-usable credential. Every
   * other state maps to an empty 404 so callers cannot distinguish refusal,
   * expiry, revocation, or a stranger's request.
   */
  @Transactional
  public PresentationView presentation(ServiceAccountPrincipal caller, UUID requestId) {
    ResourceRef resource =
        ResourceRef.tenantScoped("proof-request", requestId.toString(), caller.tenantId());
    Decision decision = authz.authorize(Optional.of(caller), Action.READ_CONSENT, resource);
    if (!decision.permitted()) {
      audit.recordDenial(caller, Action.READ_CONSENT, resource, decision.reasonCode(),
          decision.policyVersion());
      throw new ForbiddenException(decision.reasonCode());
    }
    Stored row = load(caller, requestId);
    if (!isVerified(row, clock.instant())) {
      throw new ConsentNotFoundException();
    }
    audit.record(caller, Action.READ_CONSENT, resource, decision, "",
        Map.of("request", requestId.toString(), "presentation", "delivered"));
    return new PresentationView(
        row.id(), "VERIFIED", true, PROFILE, row.consentArtifact(),
        claimsMap(row.claimsJson()), row.expiresAt(), row.trustSnapshot());
  }

  /**
   * Canonical consent message. The holder signs what the review screen
   * shows: every bound field plus the explicit decision. Changing any
   * bound value — or the decision word itself — breaks the proof.
   */
  static String consentMessage(Stored row, String decision) {
    return CONSENT_LABEL + "\n" + row.id() + "\n" + decision + "\n" + row.rpId() + "\n"
        + row.audience() + "\n" + row.purpose() + "\n" + CLAIMS_CANONICAL + "\n"
        + row.planHash() + "\n" + row.challenge() + "\n" + row.expiresAt() + "\n"
        + row.holderThumbprint();
  }

  private record Validated(String claimsJson, String holderThumbprint) {}

  record Stored(
      UUID id,
      UUID credentialId,
      String rpId,
      String audience,
      String purpose,
      String claimsJson,
      String planHash,
      String challenge,
      String holderThumbprint,
      String state,
      Instant createdAt,
      Instant expiresAt,
      String consentArtifact,
      long trustSnapshot) {}

  /**
   * Guard gate: the candidate plan must parse, be accepted against
   * live trust state and the RP-selected policy, and hash to the
   * bound plan hash. Adjudication audits its own VALIDATE_PLAN row,
   * so the consent audit trail shows the guard verdict first.
   */
  private void requireGuardAccepted(ServiceAccountPrincipal caller, CreateRequest request) {
    CandidatePlan plan = PlanParser.parsePlan(request.plan());
    SelectedPolicy selected = PlanParser.parseSelected(request.policyId(), request.policyVersion());
    GuardService.VerdictView verdict = guard.adjudicate(caller, plan, selected);
    if (!verdict.accepted()) {
      throw new GuardRejectedException(verdict.code());
    }
    if (!MessageDigest.isEqual(
        request.planHash().getBytes(StandardCharsets.UTF_8),
        PlanGuard.canonicalHash(plan).getBytes(StandardCharsets.UTF_8))) {
      throw new InvalidConsentException("plan hash does not match the approved plan");
    }
  }

  private Validated validate(CreateRequest request, Instant now) {
    if (request == null
        || blank(request.rpId()) || blank(request.audience()) || blank(request.purpose())
        || request.credentialId() == null
        || request.claims() == null
        || request.plan() == null
        || request.planHash() == null || request.challenge() == null
        || request.expiresAt() == null) {
      throw new InvalidConsentException("proof request is incomplete");
    }
    if (request.rpId().length() > 256 || request.audience().length() > 256
        || request.purpose().length() > 256) {
      throw new InvalidConsentException("proof request fields are too long");
    }
    if (!request.planHash().matches("[0-9a-f]{64}")) {
      throw new InvalidConsentException("plan hash is malformed");
    }
    if (!request.challenge().matches("[A-Za-z0-9_-]{16,128}")) {
      throw new InvalidConsentException("challenge is malformed");
    }
    if (!request.expiresAt().isAfter(now.plus(MIN_LIFETIME))
        || request.expiresAt().isAfter(now.plus(MAX_LIFETIME))) {
      throw new InvalidConsentException("validity is outside the permitted range");
    }
    allowlistClaims(request.claims());
    Credential credential = requireUsableCredential(request.credentialId());
    String claimsJson;
    try {
      claimsJson = mapper.writeValueAsString(request.claims());
    } catch (JacksonException e) {
      throw new InvalidConsentException("claims are not encodable");
    }
    return new Validated(claimsJson, credential.holderThumbprint());
  }

  private static boolean blank(String value) {
    return value == null || value.isBlank();
  }

  /** G1 synthetic allowlist, matching issuance: exactly adultOver18 true. */
  private static void allowlistClaims(Map<String, Object> claims) {
    if (claims.size() != 1 || !Boolean.TRUE.equals(claims.get("adultOver18"))) {
      throw new InvalidConsentException("claims are not permitted for this request");
    }
  }

  private record Credential(String holderThumbprint, String status, Instant expiresAt) {}

  private Credential requireUsableCredential(UUID credentialId) {
    Credential credential = credentialRow(credentialId)
        .orElseThrow(() -> new InvalidConsentException("credential is not usable for this request"));
    if (!"VALID".equals(credential.status())
        || !credential.expiresAt().isAfter(clock.instant())) {
      throw new InvalidConsentException("credential is not usable for this request");
    }
    return credential;
  }

  private Optional<Credential> credentialRow(UUID credentialId) {
    List<Credential> rows =
        tenant.query(
            "SELECT holder_thumbprint, status, expires_at FROM credential_artifact"
                + " WHERE id = ?",
            (rs, row) ->
                new Credential(
                    rs.getString("holder_thumbprint"),
                    rs.getString("status"),
                    rs.getTimestamp("expires_at").toInstant()),
            credentialId);
    return rows.isEmpty() ? Optional.empty() : Optional.of(rows.get(0));
  }

  private Stored load(ServiceAccountPrincipal caller, UUID requestId) {
    List<Stored> rows =
        tenant.query(
            "SELECT id, credential_id, rp_id, audience, purpose, claims, plan_hash, challenge,"
                + " holder_thumbprint, state, created_at, expires_at, consent_artifact,"
                + " trust_snapshot_version FROM proof_request WHERE id = ? AND tenant_id = ?",
            (rs, row) ->
                new Stored(
                    rs.getObject("id", UUID.class),
                    rs.getObject("credential_id", UUID.class),
                    rs.getString("rp_id"),
                    rs.getString("audience"),
                    rs.getString("purpose"),
                    rs.getString("claims"),
                    rs.getString("plan_hash"),
                    rs.getString("challenge"),
                    rs.getString("holder_thumbprint"),
                    rs.getString("state"),
                    rs.getTimestamp("created_at").toInstant(),
                    rs.getTimestamp("expires_at").toInstant(),
                    rs.getString("consent_artifact"),
                    rs.getLong("trust_snapshot_version")),
            requestId,
            caller.tenantId());
    if (rows.isEmpty()) {
      throw new ConsentNotFoundException();
    }
    return rows.get(0);
  }

  private RequestView view(Stored row, Instant now) {
    Derived derived = derive(row, now);
    return new RequestView(
        row.id(), row.rpId(), row.audience(), row.purpose(), row.credentialId(),
        claimsMap(row.claimsJson()), row.planHash(), row.challenge(),
        row.holderThumbprint(), derived.state(), derived.reason(),
        row.createdAt(), row.expiresAt(), row.trustSnapshot());
  }

  private record Derived(String state, String reason) {}

  private Derived derive(Stored row, Instant now) {
    if ("DENIED".equals(row.state())) {
      return new Derived("DENIED", "holder refused this request");
    }
    if (!row.expiresAt().isAfter(now)) {
      return new Derived("UNAVAILABLE", "consent request has expired");
    }
    if (!credentialUsable(row.credentialId(), now)) {
      return new Derived("UNAVAILABLE", "credential is no longer usable");
    }
    if ("APPROVED".equals(row.state())) {
      return new Derived("VERIFIED", "consent verified; presentation authorized");
    }
    return new Derived("PENDING", "awaiting the holder's explicit decision");
  }

  private boolean isVerified(Stored row, Instant now) {
    return "APPROVED".equals(row.state())
        && row.consentArtifact() != null
        && row.expiresAt().isAfter(now)
        && credentialUsable(row.credentialId(), now);
  }

  private boolean credentialUsable(UUID credentialId, Instant now) {
    return credentialRow(credentialId)
        .map(row -> "VALID".equals(row.status()) && row.expiresAt().isAfter(now))
        .orElse(false);
  }

  private ECPublicKey parseHolderKey(JsonNode holderJwk) {
    try {
      return HolderProofs.parseP256Key(holderJwk);
    } catch (HolderProofException e) {
      throw new InvalidConsentException(e.getMessage());
    }
  }

  private void verifyConsentProof(ECPublicKey holderKey, String proof, String expectedMessage) {
    if (proof == null || proof.isBlank()) {
      throw new InvalidConsentException("consent proof is missing");
    }
    try {
      HolderProofs.verifyEs256(holderKey, proof, expectedMessage, mapper);
    } catch (HolderProofException e) {
      throw new InvalidConsentException(e.getMessage());
    }
  }

  private Map<String, Object> claimsMap(String claimsJson) {
    try {
      Map<String, Object> claims = new LinkedHashMap<>();
      JsonNode node = mapper.readTree(claimsJson);
      node.properties().forEach(entry -> claims.put(entry.getKey(), scalar(entry.getValue())));
      return claims;
    } catch (JacksonException e) {
      throw new IllegalStateException("stored claims are not JSON", e);
    }
  }

  static Object scalar(JsonNode node) {
    if (node.isBoolean()) {
      return node.asBoolean();
    }
    if (node.isString()) {
      return node.asString();
    }
    if (node.isNumber()) {
      // Separate returns: a long:double ternary would widen to double.
      if (node.isIntegralNumber()) {
        return node.asLong();
      }
      return node.asDouble();
    }
    return node.toString();
  }

  private Map<String, String> detail(
      UUID requestId, CreateRequest request, String holderThumbprint, long snapshot) {
    Map<String, String> detail = new LinkedHashMap<>();
    detail.put("request", requestId.toString());
    detail.put("rp", request.rpId());
    detail.put("purpose", request.purpose());
    detail.put("holder", holderThumbprint);
    detail.put("snapshot", String.valueOf(snapshot));
    return detail;
  }
}
