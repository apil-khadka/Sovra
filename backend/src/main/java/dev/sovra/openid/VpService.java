package dev.sovra.openid;

import com.nimbusds.jose.util.Base64URL;
import dev.sovra.audit.AuditService;
import dev.sovra.audit.AuditedAuthorizer;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.auth.ServiceAccountRepository;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ResourceRef;
import dev.sovra.tenancy.TenantContext;
import dev.sovra.verification.VerificationService;
import id.walt.sdjwt.SDJwt;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;
import kotlinx.serialization.json.JsonElement;
import kotlinx.serialization.json.JsonObject;
import kotlinx.serialization.json.JsonPrimitive;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * OpenID for Verifiable Presentations (SOV-036): the G1 frozen subset
 * of OpenID4VP 1.0 Final with DCQL queries over Sovra's verification
 * control plane.
 *
 * <ul>
 *   <li>The consuming RP opens a session bound to one proof request;
 *   the service returns a {@code request_uri} serving a signed
 *   authorization request object (ES256) carrying the nonce, a DCQL
 *   query for the adult-status credential, and
 *   {@code response_mode=direct_post.jwt}.</li>
 *   <li>The wallet posts the JWE-encrypted response
 *   ({@code direct_post.jwt}, ECDH-ES+A256KW / A256GCM) with
 *   {@code vp_token} (SD-JWT VC plus KeyBinding JWT) and a
 *   presentation submission. Unencrypted {@code direct_post} is
 *   rejected outside loopback harness runs.</li>
 *   <li>The service checks transport, session, submission, and DCQL
 *   fulfillment, then delegates the decision to
 *   {@link VerificationService}, so consent, freshness, trust,
 *   replay, and audit gates are identical to the native path.</li>
 * </ul>
 *
 * <p>G1 names the verifier by the RP callback audience: the request
 * object's {@code client_id} is the proof request's audience, and the
 * KeyBinding {@code aud} must equal it. The presented SD-JWT must be
 * byte-identical to the stored full-disclosure artifact — the
 * consented claim set is the whole claim set at G1, so a conforming
 * wallet presents the issued bytes verbatim.
 */
@Service
public class VpService {

  static final Duration SESSION_TTL = Duration.ofMinutes(5);
  static final String RESPONSE_MODE = "direct_post.jwt";
  static final String JWE_ALG = "ECDH-ES+A256KW";
  static final String JWE_ENC = "A256GCM";

  private static final SecureRandom RANDOM = new SecureRandom();

  private final AuthorizationService authz;
  private final AuditService audit;
  private final ServiceAccountRepository accounts;
  private final VerificationService verification;
  private final OpenIdKeys keys;
  private final JdbcTemplate tenant;
  private final JdbcTemplate global;
  private final Clock clock;
  private final ObjectMapper mapper;
  private final org.springframework.transaction.PlatformTransactionManager transactions;
  private final String issuerBaseUrl;
  private final boolean allowPlainDirectPost;

  public VpService(
      AuthorizationService authz,
      AuditService audit,
      ServiceAccountRepository accounts,
      VerificationService verification,
      OpenIdKeys keys,
      @Qualifier("tenantJdbcTemplate") JdbcTemplate tenant,
      DataSource globalDataSource,
      Clock clock,
      ObjectMapper mapper,
      org.springframework.transaction.PlatformTransactionManager transactions,
      @Value("${sovra.openid.issuer-base-url:http://localhost:8080}") String issuerBaseUrl,
      @Value("${sovra.openid.allow-plain-direct-post:false}") boolean allowPlainDirectPost) {
    this.authz = authz;
    this.audit = audit;
    this.accounts = accounts;
    this.verification = verification;
    this.keys = keys;
    this.tenant = tenant;
    this.global = new JdbcTemplate(globalDataSource);
    this.clock = clock;
    this.mapper = mapper;
    this.transactions = transactions;
    this.issuerBaseUrl = issuerBaseUrl;
    this.allowPlainDirectPost = allowPlainDirectPost;
  }

  /** Opens a VP session for one proof request (consuming RP). */
  @Transactional
  public String createRequest(ServiceAccountPrincipal caller, UUID proofRequestId) {
    ResourceRef resource =
        ResourceRef.tenantScoped("vp-session", "requests", caller.tenantId());
    Decision decision = AuditedAuthorizer.require(authz, audit, caller,
        Action.VP_CREATE_REQUEST, resource);
    if (proofRequestId == null) {
      throw new InvalidOpenIdRequestException("proof request is missing");
    }
    StoredRequest stored = loadRequest(proofRequestId, caller.tenantId())
        .orElseThrow(OpenIdNotFoundException::new);
    Instant now = clock.instant();
    UUID sessionId = UUID.randomUUID();
    String nonce = nonce();
    tenant.update(
        "INSERT INTO vp_session (id, tenant_id, proof_request_id, nonce, state,"
            + " expires_at, created_by, created_account)"
            + " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        sessionId, caller.tenantId(), proofRequestId, nonce, VpSessionState.PENDING.name(),
        java.sql.Timestamp.from(now.plus(SESSION_TTL)), caller.name(), caller.id());
    audit.record(caller, Action.VP_CREATE_REQUEST,
        ResourceRef.tenantScoped("vp-session", sessionId.toString(), caller.tenantId()),
        decision, "", Map.of("session", sessionId.toString(), "audience", stored.audience()));
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("session_id", sessionId.toString());
    body.put("request_uri", issuerBaseUrl + "/api/vp/requests/" + sessionId + "/object");
    body.put("expires_in", SESSION_TTL.toSeconds());
    return json(body);
  }

  /** Signed authorization request object (public wallet fetch). */
  public String requestObject(UUID sessionId) {
    Session session = findSession(sessionId).orElseThrow(OpenIdNotFoundException::new);
    if (!session.expiresAt().isAfter(clock.instant())) {
      throw new OpenIdProtocolException("invalid_request");
    }
    ServiceAccountPrincipal creator = liveCreator(session.createdAccount());
    StoredRequest stored =
        TenantContext.withResult(creator, () -> loadRequest(session.proofRequestId(), creator.tenantId())
            .orElseThrow(OpenIdNotFoundException::new));
    Map<String, Object> metadata = new LinkedHashMap<>();
    metadata.put("jwks_uri", issuerBaseUrl + "/api/vp/jwks.json");
    metadata.put("authorization_encrypted_response_alg", JWE_ALG);
    metadata.put("authorization_encrypted_response_enc", JWE_ENC);
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("iss", stored.audience());
    claims.put("client_id", stored.audience());
    claims.put("response_type", "vp_token");
    claims.put("response_mode", RESPONSE_MODE);
    claims.put("response_uri", issuerBaseUrl + "/api/vp/responses/" + session.id());
    claims.put("nonce", session.nonce());
    claims.put("state", session.id().toString());
    claims.put("iat", clock.instant().getEpochSecond());
    claims.put("exp", session.expiresAt().getEpochSecond());
    claims.put("dcql_query", Dcql.queryFor(stored.vct()));
    claims.put("client_metadata", metadata);
    return keys.signRequestObject(claims);
  }

  /** Verifier public JWKS (signing + response-encryption key). */
  public String jwks() {
    return json(keys.jwks());
  }

  /**
   * Submits a {@code direct_post.jwt} response (public wallet call).
   * Either {@code response} (JWE) or, only on loopback harness runs
   * with the explicit flag, a plain {@code vp_token} plus
   * {@code presentation_submission}. Transport, session, state, and
   * DCQL problems are {@code invalid_request}; everything else
   * delegates to verification and returns its 200 decision body.
   */
  @Transactional
  public String submitResponse(
      UUID sessionId, String response, String vpToken, String submission, boolean loopback) {
    if (sessionId == null) {
      throw new InvalidOpenIdRequestException("session is missing");
    }
    Session session = findSession(sessionId).orElseThrow(OpenIdNotFoundException::new);
    ServiceAccountPrincipal creator = liveCreator(session.createdAccount());
    if (session.state() == VpSessionState.COMPLETED) {
      // Idempotent replay: the stored decision returns verbatim,
      // whenever it is asked for. No re-decision, no new decision
      // row, no new audit rows — expiry cannot un-decide a session.
      return replayStored(session, creator);
    }
    if (!session.expiresAt().isAfter(clock.instant())) {
      // Commits in its own transaction: the rejection below rolls
      // back this call's transaction, not the expiry marking.
      TenantContext.withResult(creator, () -> expireNewTransaction(session.id()));
      throw new OpenIdProtocolException("invalid_request");
    }
    // The completion UPDATE below re-checks PENDING so concurrent
    // submits cannot both win.
    if (session.state() != VpSessionState.PENDING) {
      throw new OpenIdProtocolException("invalid_request");
    }
    if (response != null && !response.isBlank()) {
      return submitEncrypted(session, creator, response);
    }
    if (vpToken != null && !vpToken.isBlank()) {
      if (!allowPlainDirectPost || !loopback) {
        throw new OpenIdProtocolException("invalid_request");
      }
      return submitPlain(session, creator, vpToken, submission);
    }
    throw new InvalidOpenIdRequestException("response is missing");
  }

  private String submitEncrypted(Session session, ServiceAccountPrincipal creator, String jwe) {
    if (jwe.length() > 32 * 1024) {
      throw new InvalidOpenIdRequestException("response is too large");
    }
    String payload = keys.decryptResponse(jwe);
    JsonNode body;
    try {
      body = mapper.readTree(payload);
    } catch (Exception e) {
      throw new InvalidOpenIdRequestException("response payload is malformed");
    }
    if (!session.id().toString().equals(text(body, "state"))) {
      throw new OpenIdProtocolException("invalid_request");
    }
    String vpToken = text(body, "vp_token");
    JsonNode submission = body.get("presentation_submission");
    if (vpToken == null || vpToken.isBlank() || submission == null || !submission.isObject()) {
      throw new InvalidOpenIdRequestException("response is incomplete");
    }
    return decide(session, creator, vpToken, submission);
  }

  private String submitPlain(
      Session session, ServiceAccountPrincipal creator, String vpToken, String submissionRaw) {
    JsonNode submission;
    try {
      submission =
          submissionRaw == null ? null : mapper.readTree(submissionRaw);
    } catch (Exception e) {
      throw new InvalidOpenIdRequestException("submission is malformed");
    }
    if (submission == null || !submission.isObject()) {
      throw new InvalidOpenIdRequestException("response is incomplete");
    }
    return decide(session, creator, vpToken, submission);
  }

  private String decide(
      Session session, ServiceAccountPrincipal creator, String vpToken, JsonNode submission) {
    if (vpToken.length() > 32 * 1024) {
      throw new InvalidOpenIdRequestException("presentation is too large");
    }
    requireSubmissionShape(submission);
    int split = vpToken.lastIndexOf('~');
    if (split <= 0 || split == vpToken.length() - 1) {
      throw new InvalidOpenIdRequestException("presentation must carry a key binding");
    }
    // Combined presentation form: <stored-artifact>~<kb-jwt>. The
    // stored G1 artifact carries no trailing tilde, so the SD-JWT
    // portion ends exactly at the separator.
    String presented = vpToken.substring(0, split);
    String kbJwt = vpToken.substring(split + 1);
    return TenantContext.withResult(creator, () -> {
      StoredRequest stored =
          loadRequest(session.proofRequestId(), creator.tenantId())
              .orElseThrow(OpenIdNotFoundException::new);
      Credential credential = loadCredential(stored.credentialId())
          .orElseThrow(OpenIdNotFoundException::new);
      // G1 presents the issued bytes verbatim; anything else names a
      // different credential than the consented one.
      if (!MessageDigest.isEqual(
          presented.getBytes(StandardCharsets.US_ASCII),
          credential.artifact().getBytes(StandardCharsets.US_ASCII))) {
        throw new OpenIdProtocolException("invalid_request");
      }
      requireDcqlFulfilled(presented, stored);
      VerificationService.VerifyRequest delegated =
          new VerificationService.VerifyRequest(
              session.proofRequestId(), session.nonce(), stored.audience(),
              credential.holderJwk(), kbJwt);
      String decision = verification.verify(creator, delegated);
      UUID decisionId = decisionId(decision);
      int completed =
          tenant.update(
              "UPDATE vp_session SET state = ?, decision_id = ? WHERE id = ? AND state = ?",
              VpSessionState.COMPLETED.name(), decisionId, session.id(),
              VpSessionState.PENDING.name());
      if (completed != 1) {
        throw new OpenIdProtocolException("invalid_request");
      }
      return decision;
    });
  }

  private void requireSubmissionShape(JsonNode submission) {
    JsonNode descriptors = submission.get("descriptor_map");
    if (descriptors == null || !descriptors.isArray() || descriptors.size() != 1) {
      throw new InvalidOpenIdRequestException("submission shape is unsupported");
    }
    JsonNode descriptor = descriptors.get(0);
    if (!Dcql.CLAIM_ID.equals(text(descriptor, "id"))
        || !"dc+sd-jwt".equals(text(descriptor, "format"))) {
      throw new InvalidOpenIdRequestException("submission shape is unsupported");
    }
  }

  private void requireDcqlFulfilled(String presented, StoredRequest stored) {
    SDJwt parsed;
    try {
      parsed = SDJwt.Companion.parse(presented);
    } catch (RuntimeException e) {
      throw new InvalidOpenIdRequestException("presentation is malformed");
    }
    JsonObject payload;
    try {
      payload = parsed.getFullPayload();
    } catch (RuntimeException e) {
      throw new InvalidOpenIdRequestException("presentation is malformed");
    }
    String vct = payloadText(payload, "vct");
    JsonElement claims = payload.get("claims");
    JsonNode disclosed = toJackson(claims);
    JsonNode query;
    try {
      query = mapper.readTree(json(Dcql.queryFor(stored.vct())));
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
    Optional<String> mismatch = Dcql.match(query, "dc+sd-jwt", vct, disclosed);
    if (mismatch.isPresent()) {
      throw new OpenIdProtocolException("invalid_request");
    }
  }

  private record Session(UUID id, UUID proofRequestId, String nonce, VpSessionState state,
      Instant expiresAt, UUID createdAccount, UUID decisionId) {}

  /**
   * Returns the stored decision bytes verbatim. The decision id comes
   * from our own session row, never from the caller, and the tenant
   * predicate holds anyway.
   */
  private String replayStored(Session session, ServiceAccountPrincipal creator) {
    return TenantContext.withResult(
        creator,
        () -> {
          List<String> rows =
              tenant.query(
                  "SELECT response_body FROM verification_decision WHERE id = ? AND tenant_id = ?",
                  (rs, row) -> rs.getString(1),
                  session.decisionId(), creator.tenantId());
          if (rows.isEmpty()) {
            throw new IllegalStateException("decision record vanished");
          }
          return rows.get(0);
        });
  }

  private record StoredRequest(UUID credentialId, String audience, String vct) {}

  private record Credential(String artifact, JsonNode holderJwk) {}

  private Optional<Session> findSession(UUID sessionId) {
    List<Session> rows =
        global.query(
            "SELECT id, proof_request_id, nonce, state, expires_at, created_account, decision_id"
                + " FROM resolve_vp_session(?)",
            (rs, row) ->
                new Session(
                    rs.getObject("id", UUID.class),
                    rs.getObject("proof_request_id", UUID.class),
                    rs.getString("nonce"),
                    VpSessionState.from(rs.getString("state")),
                    rs.getTimestamp("expires_at").toInstant(),
                    rs.getObject("created_account", UUID.class),
                    rs.getObject("decision_id", UUID.class)),
            sessionId);
    return rows.stream().findFirst();
  }

  private Void expireNewTransaction(UUID sessionId) {
    org.springframework.transaction.support.TransactionTemplate template =
        new org.springframework.transaction.support.TransactionTemplate(transactions);
    template.setPropagationBehavior(
        org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    template.execute(
        ignored -> {
          tenant.update(
              "UPDATE vp_session SET state = ? WHERE id = ? AND state = ?",
              VpSessionState.EXPIRED.name(), sessionId, VpSessionState.PENDING.name());
          return null;
        });
    return null;
  }

  private ServiceAccountPrincipal liveCreator(UUID accountId) {
    var account = accounts.findLive(accountId);
    if (account.isEmpty() || !account.get().live(clock.instant())) {
      throw new OpenIdProtocolException("invalid_request");
    }
    return account.get().principal();
  }

  private Optional<StoredRequest> loadRequest(UUID proofRequestId, UUID tenantId) {
    List<StoredRequest> rows =
        tenant.query(
            "SELECT p.audience AS audience, c.vct AS vct, p.credential_id AS credential_id"
                + " FROM proof_request p JOIN credential_artifact c ON c.id = p.credential_id"
                + " WHERE p.id = ? AND p.tenant_id = ?",
            (rs, row) ->
                new StoredRequest(
                    rs.getObject("credential_id", UUID.class),
                    rs.getString("audience"),
                    rs.getString("vct")),
            proofRequestId,
            tenantId);
    return rows.stream().findFirst();
  }

  private Optional<Credential> loadCredential(UUID credentialId) {
    List<Credential> rows =
        tenant.query(
            "SELECT artifact, holder_thumbprint FROM credential_artifact WHERE id = ?",
            (rs, row) -> {
              String artifact = rs.getString("artifact");
              return new Credential(artifact, holderJwkFrom(artifact));
            },
            credentialId);
    return rows.stream().findFirst();
  }

  /**
   * Holder key for the delegated submission, derived from the stored
   * artifact's {@code cnf} — never from wallet-supplied bytes.
   */
  private JsonNode holderJwkFrom(String artifact) {
    try {
      SDJwt parsed = SDJwt.Companion.parse(artifact);
      JsonElement cnf = parsed.getFullPayload().get("cnf");
      JsonElement jwk = cnf instanceof JsonObject object ? object.get("jwk") : null;
      if (!(jwk instanceof JsonObject key)) {
        throw new InvalidOpenIdRequestException("credential binding is malformed");
      }
      return toJackson(jwk);
    } catch (InvalidOpenIdRequestException e) {
      throw e;
    } catch (RuntimeException e) {
      throw new InvalidOpenIdRequestException("credential binding is malformed");
    }
  }

  private UUID decisionId(String decisionJson) {
    try {
      return UUID.fromString(mapper.readTree(decisionJson).get("decisionId").asString());
    } catch (Exception e) {
      throw new IllegalStateException("decision response is malformed", e);
    }
  }

  static String nonce() {
    byte[] raw = new byte[24];
    RANDOM.nextBytes(raw);
    return Base64URL.encode(raw).toString();
  }

  private static String text(JsonNode node, String field) {
    JsonNode child = node == null ? null : node.get(field);
    return child != null && child.isString() ? child.asString() : null;
  }

  private static String payloadText(JsonObject payload, String field) {
    JsonElement child = payload == null ? null : payload.get(field);
    if (child instanceof JsonPrimitive primitive && primitive.isString()) {
      return primitive.getContent();
    }
    return null;
  }

  /** Minimal kotlinx-to-Jackson bridge for the small G1 claim shapes. */
  private JsonNode toJackson(JsonElement element) {
    try {
      return mapper.readTree(element.toString());
    } catch (Exception e) {
      throw new InvalidOpenIdRequestException("presentation claims are malformed");
    }
  }

  private String json(Map<String, Object> body) {
    try {
      return mapper.writeValueAsString(body);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }
}
