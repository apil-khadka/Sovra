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
import dev.sovra.authz.ReasonCode;
import dev.sovra.authz.ResourceRef;
import dev.sovra.issuance.InvalidIssuanceException;
import dev.sovra.issuance.IssuanceService;
import dev.sovra.issuance.LocalDevSigner;
import dev.sovra.trust.TrustSnapshotProvider;
import dev.sovra.tenancy.TenantContext;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * OpenID for Verifiable Credential Issuance (SOV-036): the G1 frozen
 * subset of OpenID4VCI 1.0 Final over Sovra's issuance control plane.
 *
 * <ul>
 *   <li>{@code pre-authorized_code} first: an issuer operator publishes
 *   an offer carrying a single-use code; the wallet redeems it at the
 *   token endpoint (no client authentication — public wallet).</li>
 *   <li>{@code authorization_code} against Sovra's synthetic
 *   authorization server: the holder's tenant agent completes the
 *   authorize call (transport-authenticated), binding a PKCE S256
 *   challenge; the wallet redeems the code with the verifier.</li>
 *   <li>The credential endpoint takes one {@code jwt} proof bound to
 *   the token's single-use {@code c_nonce} and delegates to
 *   {@link IssuanceService#issueVci}, so trust, allowlist, holder-key,
 *   idempotency, and audit gates are identical to the native path.</li>
 * </ul>
 *
 * <p>Wallet-facing calls (token, nonce, credential) carry no service
 * account: the tenant resolves from the grant, and the grant creator's
 * account is re-validated live before any issuance. Codes, tokens,
 * and nonces are 256-bit CSPRNG values stored as hashes, with 5-minute
 * lifetimes and atomic single-use consumption. G1 serves exactly one
 * credential configuration ({@value #CONFIGURATION_ID}); batch
 * requests, transaction codes, and pushed authorization requests are
 * rejected, not partially honored.
 */
@Service
public class VciService {

  static final Duration GRANT_TTL = Duration.ofMinutes(5);
  static final Duration TOKEN_TTL = Duration.ofMinutes(5);
  static final Duration NONCE_TTL = Duration.ofMinutes(5);
  static final Duration CREDENTIAL_VALIDITY = Duration.ofDays(365);
  static final String CONFIGURATION_ID = "sovra-adult-status-1";
  static final String FORMAT = "dc+sd-jwt";
  static final String PRE_AUTH_GRANT =
      "urn:ietf:params:oauth:grant-type:pre-authorized_code";
  static final String AUTH_CODE_GRANT = "authorization_code";

  private static final SecureRandom RANDOM = new SecureRandom();

  private final AuthorizationService authz;
  private final AuditService audit;
  private final TrustSnapshotProvider snapshots;
  private final IssuanceService issuance;
  private final ServiceAccountRepository accounts;
  private final JdbcTemplate tenant;
  private final JdbcTemplate global;
  private final Clock clock;
  private final ObjectMapper mapper;
  private final String issuerBaseUrl;

  public VciService(
      AuthorizationService authz,
      AuditService audit,
      TrustSnapshotProvider snapshots,
      IssuanceService issuance,
      ServiceAccountRepository accounts,
      @Qualifier("tenantJdbcTemplate") JdbcTemplate tenant,
      DataSource globalDataSource,
      Clock clock,
      ObjectMapper mapper,
      @Value("${sovra.openid.issuer-base-url:http://localhost:8080}") String issuerBaseUrl) {
    this.authz = authz;
    this.audit = audit;
    this.snapshots = snapshots;
    this.issuance = issuance;
    this.accounts = accounts;
    this.tenant = tenant;
    this.global = new JdbcTemplate(globalDataSource);
    this.clock = clock;
    this.mapper = mapper;
    this.issuerBaseUrl = issuerBaseUrl;
  }

  /** Credential-issuer metadata (public; pinned G1 subset). */
  public String metadata() {
    String issuer = LocalDevSigner.ISSUER_ID;
    Map<String, Object> configuration = new LinkedHashMap<>();
    configuration.put("format", FORMAT);
    configuration.put("vct", dev.sovra.issuance.SyntheticJwtEncoder.ADULT_VCT);
    configuration.put("scope", "sovra-adult-status");
    configuration.put("cryptographic_binding_methods_supported", List.of("jwk"));
    configuration.put("credential_signing_alg_values_supported", List.of("ES256"));
    configuration.put(
        "proof_types_supported",
        Map.of(
            "jwt",
            Map.of("proof_signing_alg_values_supported", List.of("ES256"))));
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("credential_issuer", issuer);
    body.put("authorization_servers", List.of(issuerBaseUrl + "/api/vci"));
    body.put("credential_endpoint", issuerBaseUrl + "/api/vci/credential");
    body.put("token_endpoint", issuerBaseUrl + "/api/vci/token");
    body.put("nonce_endpoint", issuerBaseUrl + "/api/vci/nonce");
    body.put("credential_configurations_supported", Map.of(CONFIGURATION_ID, configuration));
    return json(body);
  }

  /** Publishes a pre-authorized credential offer (issuer operator). */
  @Transactional
  public String createOffer(ServiceAccountPrincipal caller, String issuerId, String vct) {
    ResourceRef resource =
        ResourceRef.tenantScoped("vci-offer", "offers", caller.tenantId());
    Decision decision = AuditedAuthorizer.require(authz, audit, caller,
        Action.VCI_CREATE_OFFER, resource);
    requireKnownConfiguration(issuerId, vct);
    requireTrustedNow(issuerId, vct);
    Instant now = clock.instant();
    String code = random();
    UUID grantId = UUID.randomUUID();
    tenant.update(
        "INSERT INTO vci_grant (id, tenant_id, kind, issuer_id, vct, code_hash,"
            + " pkce_challenge, created_by, created_account, expires_at)"
            + " VALUES (?, ?, 'PRE_AUTH', ?, ?, ?, NULL, ?, ?, ?)",
        grantId, caller.tenantId(), issuerId, vct, hash(code), caller.name(), caller.id(),
        java.sql.Timestamp.from(now.plus(GRANT_TTL)));
    Map<String, Object> grant = Map.of(
        "pre-authorized_code",
        Map.of("pre-authorized_code", code));
    Map<String, Object> offer = new LinkedHashMap<>();
    // The offer names the credential issuer identifier, identical to
    // the metadata document — never the deployment base URL.
    offer.put("credential_issuer", issuerId);
    offer.put("credential_configuration_ids", List.of(CONFIGURATION_ID));
    offer.put("grants", grant);
    audit.record(caller, Action.VCI_CREATE_OFFER,
        ResourceRef.tenantScoped("vci-offer", grantId.toString(), caller.tenantId()),
        decision, "", Map.of("grant", grantId.toString(), "vct", vct));
    return json(Map.of(
        "credential_offer", offer,
        "credential_offer_uri",
        "openid-credential-offer://?credential_offer=" + urlEncode(json(offer))));
  }

  /**
   * Synthetic authorization server (holder agent, transport
   * authenticated): binds a PKCE S256 challenge and returns a
   * single-use authorization code. Production replaces this desk
   * with the Keycloak-backed AS; the code contract stays the same.
   */
  @Transactional
  public String authorize(
      ServiceAccountPrincipal caller, String issuerId, String vct, String codeChallenge) {
    ResourceRef resource =
        ResourceRef.tenantScoped("vci-grant", "authorize", caller.tenantId());
    Decision decision = AuditedAuthorizer.require(authz, audit, caller,
        Action.VCI_AUTHORIZE, resource);
    requireKnownConfiguration(issuerId, vct);
    requireTrustedNow(issuerId, vct);
    if (codeChallenge == null || !codeChallenge.matches("[A-Za-z0-9_-]{43,128}")) {
      throw new InvalidOpenIdRequestException("pkce challenge is malformed");
    }
    Instant now = clock.instant();
    String code = random();
    UUID grantId = UUID.randomUUID();
    tenant.update(
        "INSERT INTO vci_grant (id, tenant_id, kind, issuer_id, vct, code_hash,"
            + " pkce_challenge, created_by, created_account, expires_at)"
            + " VALUES (?, ?, 'AUTH_CODE', ?, ?, ?, ?, ?, ?, ?)",
        grantId, caller.tenantId(), issuerId, vct, hash(code), codeChallenge, caller.name(),
        caller.id(), java.sql.Timestamp.from(now.plus(GRANT_TTL)));
    audit.record(caller, Action.VCI_AUTHORIZE,
        ResourceRef.tenantScoped("vci-grant", grantId.toString(), caller.tenantId()),
        decision, "", Map.of("grant", grantId.toString(), "vct", vct));
    return json(Map.of("code", code, "expires_in", GRANT_TTL.toSeconds()));
  }

  /**
   * Token redemption (public wallet call). The grant alone authorizes:
   * unknown, expired, or already-consumed grants all answer
   * {@code invalid_grant} without distinguishing detail.
   */
  @Transactional
  public String token(String grantType, String code, String verifier) {
    if (!PRE_AUTH_GRANT.equals(grantType) && !AUTH_CODE_GRANT.equals(grantType)) {
      throw new OpenIdProtocolException("unsupported_grant_type");
    }
    if (code == null || code.isBlank()) {
      throw new OpenIdProtocolException("invalid_request");
    }
    Instant now = clock.instant();
    Grant grant = findGrant(hash(code)).orElseThrow(() -> new OpenIdProtocolException("invalid_grant"));
    if (!grant.kind().equals(PRE_AUTH_GRANT.equals(grantType) ? "PRE_AUTH" : "AUTH_CODE")
        || !grant.expiresAt().isAfter(now)
        || grant.consumedAt() != null) {
      throw new OpenIdProtocolException("invalid_grant");
    }
    if ("AUTH_CODE".equals(grant.kind())) {
      requirePkce(verifier, grant.pkceChallenge());
    }
    ServiceAccountPrincipal creator = liveCreator(grant);
    String accessToken = random();
    String cNonce = random();
    UUID tokenId = UUID.randomUUID();
    TenantContext.with(creator, () -> {
      int consumed =
          tenant.update(
              "UPDATE vci_grant SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL",
              java.sql.Timestamp.from(now), grant.id());
      if (consumed != 1) {
        // Lost a redemption race: the winner's token stands.
        throw new OpenIdProtocolException("invalid_grant");
      }
      tenant.update(
          "INSERT INTO vci_token (id, tenant_id, grant_id, token_hash, c_nonce,"
              + " c_nonce_expires_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
          tokenId, creator.tenantId(), grant.id(), hash(accessToken), cNonce,
          java.sql.Timestamp.from(now.plus(NONCE_TTL)),
          java.sql.Timestamp.from(now.plus(TOKEN_TTL)));
    });
    TenantContext.with(creator, () -> audit.recordExternal(
        "openid-wallet", creator.tenantId(), grant.id().toString(),
        "PRE_AUTH".equals(grant.kind()) ? Action.VCI_CREATE_OFFER : Action.VCI_AUTHORIZE,
        ResourceRef.tenantScoped("vci-token", tokenId.toString(), creator.tenantId()),
        Decision.permit(authz.policyVersion()), "",
        Map.of("grant", grant.id().toString())));
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("access_token", accessToken);
    body.put("token_type", "Bearer");
    body.put("expires_in", TOKEN_TTL.toSeconds());
    body.put("c_nonce", cNonce);
    body.put("c_nonce_expires_in", NONCE_TTL.toSeconds());
    return json(body);
  }

  /** Rotates the holder-proof nonce for a live token (public wallet call). */
  @Transactional
  public String refreshNonce(String authorization) {
    Instant now = clock.instant();
    Token token = requireToken(authorization, now);
    String cNonce = random();
    TenantContext.with(token.creator(), () -> {
      int rotated =
          tenant.update(
              "UPDATE vci_token SET c_nonce = ?, c_nonce_expires_at = ?"
                  + " WHERE id = ? AND credential_issued = FALSE",
              cNonce, java.sql.Timestamp.from(now.plus(NONCE_TTL)), token.id());
      if (rotated != 1) {
        throw new OpenIdProtocolException("invalid_grant");
      }
    });
    return json(Map.of("c_nonce", cNonce));
  }

  /**
   * Credential issuance (public wallet call, bearer-bound). Consumes
   * the {@code c_nonce} atomically, then delegates to the issuance
   * control plane with the grant's authority — identical trust,
   * allowlist, key, idempotency, and audit gates as native issuance.
   */
  @Transactional
  public String credential(String authorization, JsonNode body) {
    if (body == null || !body.isObject()) {
      throw new InvalidOpenIdRequestException("credential request is malformed");
    }
    if (!FORMAT.equals(text(body, "format"))
        || !CONFIGURATION_ID.equals(text(body, "credential_configuration_id"))) {
      throw new OpenIdProtocolException("invalid_credential_request");
    }
    if (body.get("credential_requests") != null) {
      throw new OpenIdProtocolException("invalid_credential_request");
    }
    JsonNode proof = body.get("proof");
    if (proof == null
        || !"jwt".equals(text(proof, "proof_type"))
        || text(proof, "jwt") == null) {
      throw new OpenIdProtocolException("invalid_proof");
    }
    Instant now = clock.instant();
    Token token = requireToken(authorization, now);
    String cNonce = token.cNonce();
    if (cNonce == null || !token.cNonceExpiresAt().isAfter(now)) {
      throw new OpenIdProtocolException("invalid_proof");
    }
    JsonNode holderJwk = proofJwk(proof.get("jwt").asString());
    Action authority =
        "PRE_AUTH".equals(token.grantKind()) ? Action.ISSUE_CREDENTIAL : Action.VCI_AUTHORIZE;
    String response =
        TenantContext.withResult(token.creator(), () -> {
          int consumed =
              tenant.update(
                  "UPDATE vci_token SET c_nonce = NULL, c_nonce_expires_at = NULL"
                      + " WHERE id = ? AND credential_issued = FALSE AND c_nonce = ?",
                  token.id(), cNonce);
          if (consumed != 1) {
            throw new OpenIdProtocolException("invalid_proof");
          }
          String issued;
          try {
            issued =
                issuance.issueVci(
                    token.creator(),
                    new IssuanceService.IssueRequest(
                        token.issuerId(), token.vct(), holderJwk, proof.get("jwt").asString(),
                        Map.of("adultOver18", Boolean.TRUE), now.plus(CREDENTIAL_VALIDITY)),
                    "vci-" + token.id().toString().replace("-", ""),
                    cNonce,
                    authority);
          } catch (InvalidIssuanceException e) {
            // Proof, shape, and scope failures are the wallet's
            // error; dependency outages propagate unchanged.
            throw new OpenIdProtocolException("invalid_proof");
          }
          tenant.update(
              "UPDATE vci_token SET credential_issued = TRUE WHERE id = ?", token.id());
          return issued;
        });
    String artifact;
    try {
      artifact = mapper.readTree(response).get("artifact").asString();
    } catch (Exception e) {
      throw new IllegalStateException("issuance response is malformed", e);
    }
    return json(Map.of("credentials", List.of(Map.of("credential", artifact))));
  }

  private record Grant(UUID id, UUID tenantId, String kind, String issuerId, String vct,
      String pkceChallenge, UUID createdAccount, Instant expiresAt, Instant consumedAt) {}

  private record Token(UUID id, ServiceAccountPrincipal creator, String grantKind, String issuerId,
      String vct, String cNonce, Instant cNonceExpiresAt) {}

  private Optional<Grant> findGrant(String codeHash) {
    List<Grant> rows =
        global.query(
            "SELECT id, tenant_id, kind, issuer_id, vct, pkce_challenge, created_account,"
                + " expires_at, consumed_at FROM resolve_vci_grant(?)",
            (rs, row) ->
                new Grant(
                    rs.getObject("id", UUID.class),
                    rs.getObject("tenant_id", UUID.class),
                    rs.getString("kind"),
                    rs.getString("issuer_id"),
                    rs.getString("vct"),
                    rs.getString("pkce_challenge"),
                    rs.getObject("created_account", UUID.class),
                    rs.getTimestamp("expires_at").toInstant(),
                    rs.getTimestamp("consumed_at") == null
                        ? null : rs.getTimestamp("consumed_at").toInstant()),
            codeHash);
    return rows.stream().findFirst();
  }

  private Token requireToken(String authorization, Instant now) {
    String bearer = bearer(authorization);
    if (bearer == null) {
      throw new OpenIdProtocolException("invalid_token");
    }
    List<Map<String, Object>> rows =
        global.queryForList(
            "SELECT id AS id, grant_id AS grant_id, c_nonce AS c_nonce,"
                + " c_nonce_expires_at AS c_nonce_expires_at, expires_at AS expires_at,"
                + " credential_issued AS credential_issued, kind AS kind,"
                + " issuer_id AS issuer_id, vct AS vct, created_account AS created_account"
                + " FROM resolve_vci_token(?)",
            hash(bearer));
    if (rows.isEmpty()) {
      throw new OpenIdProtocolException("invalid_token");
    }
    Map<String, Object> row = rows.get(0);
    Instant expiresAt = ((java.sql.Timestamp) row.get("expires_at")).toInstant();
    if (!expiresAt.isAfter(now) || Boolean.TRUE.equals(row.get("credential_issued"))) {
      throw new OpenIdProtocolException("invalid_token");
    }
    Grant grant =
        new Grant(
            (UUID) row.get("grant_id"), null, (String) row.get("kind"),
            (String) row.get("issuer_id"), (String) row.get("vct"), null,
            (UUID) row.get("created_account"), expiresAt, null);
    ServiceAccountPrincipal creator = liveCreator(grant);
    java.sql.Timestamp nonceExpiry = (java.sql.Timestamp) row.get("c_nonce_expires_at");
    return new Token(
        (UUID) row.get("id"), creator, grant.kind(), grant.issuerId(), grant.vct(),
        (String) row.get("c_nonce"),
        nonceExpiry == null ? Instant.EPOCH : nonceExpiry.toInstant());
  }

  private ServiceAccountPrincipal liveCreator(Grant grant) {
    var account = accounts.findLive(grant.createdAccount());
    if (account.isEmpty() || !account.get().live(clock.instant())) {
      throw new OpenIdProtocolException("invalid_grant");
    }
    return account.get().principal();
  }

  private void requireKnownConfiguration(String issuerId, String vct) {
    if (!LocalDevSigner.ISSUER_ID.equals(issuerId)
        || !dev.sovra.issuance.SyntheticJwtEncoder.ADULT_VCT.equals(vct)) {
      throw new InvalidOpenIdRequestException("credential configuration is unknown");
    }
  }

  /** Fail fast when the issuer is not currently authorized; issuance rechecks live. */
  private void requireTrustedNow(String issuerId, String vct) {
    Instant now = clock.instant();
    boolean trusted =
        snapshots.current()
            .map(
                snapshot ->
                    snapshot.issuers().stream()
                        .anyMatch(
                            issuer ->
                                issuerId.equals(issuer.issuerId())
                                    && dev.sovra.trust.IssuerKeys.usable(issuer, now)
                                    && issuer.credentialTypes().contains(vct)))
            .orElse(false);
    if (!trusted) {
      throw new InvalidOpenIdRequestException("issuer is not trusted");
    }
  }

  private void requirePkce(String verifier, String challenge) {
    if (verifier == null || verifier.length() > 128 || challenge == null) {
      throw new OpenIdProtocolException("invalid_grant");
    }
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256")
              .digest(verifier.getBytes(StandardCharsets.US_ASCII));
      String computed = Base64URL.encode(digest).toString();
      if (!MessageDigest.isEqual(
          computed.getBytes(StandardCharsets.US_ASCII),
          challenge.getBytes(StandardCharsets.US_ASCII))) {
        throw new OpenIdProtocolException("invalid_grant");
      }
    } catch (OpenIdProtocolException e) {
      throw e;
    } catch (Exception e) {
      throw new OpenIdProtocolException("invalid_grant");
    }
  }

  private JsonNode proofJwk(String proof) {
    try {
      String[] parts = proof.split("\\.", -1);
      if (parts.length != 3) {
        throw new OpenIdProtocolException("invalid_proof");
      }
      JsonNode header = mapper.readTree(Base64URL.from(parts[0]).decode());
      JsonNode jwk = header.get("jwk");
      if (jwk == null || !jwk.isObject()) {
        throw new OpenIdProtocolException("invalid_proof");
      }
      return jwk;
    } catch (OpenIdProtocolException e) {
      throw e;
    } catch (Exception e) {
      throw new OpenIdProtocolException("invalid_proof");
    }
  }

  private static String bearer(String authorization) {
    if (authorization == null || authorization.length() > 512) {
      return null;
    }
    if (authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
      String token = authorization.substring(7).trim();
      return token.isEmpty() ? null : token;
    }
    return null;
  }

  private static String text(JsonNode node, String field) {
    JsonNode child = node == null ? null : node.get(field);
    return child != null && child.isString() ? child.asString() : null;
  }

  static String random() {
    byte[] raw = new byte[32];
    RANDOM.nextBytes(raw);
    return Base64URL.encode(raw).toString();
  }

  static String hash(String secret) {
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256").digest(secret.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static String urlEncode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }

  private String json(Map<String, Object> body) {
    try {
      return mapper.writeValueAsString(body);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }
}
