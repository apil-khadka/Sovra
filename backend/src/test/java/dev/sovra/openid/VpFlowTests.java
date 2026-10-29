package dev.sovra.openid;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.consent.ConsentFixtures;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import dev.sovra.verification.VerificationFixtures;
import dev.sovra.verification.VerificationFixtures.Stage;
import dev.sovra.verification.VerificationService;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * SOV-036 OpenID4VP flows over HTTP: signed request objects with DCQL,
 * encrypted {@code direct_post.jwt} responses, KeyBinding-bound
 * decisions, replay identity, and transport rejections. The wallet
 * side is {@link NimbusWallet} throughout.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = "sovra.profile=sdjwt-vc")
class VpFlowTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  @Autowired TrustService trust;

  @Autowired ObjectMapper mapper;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() throws Exception {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
    IssuanceFixtures.ensureSyntheticIssuer(owner, trust, mapper);
  }

  /** Wallet view of a VP session: request object claims + verifier key. */
  private record SessionView(String sessionId, Map<String, Object> request, String verifierJwk) {}

  private SessionView openSession(Stage stage) throws Exception {
    Map<String, Object> created =
        OpenIdFixtures.vpRequest(client, stage.rp(), stage.requestId());
    String sessionId = created.get("session_id").toString();
    assertThat(created.get("request_uri").toString())
        .endsWith("/api/vp/requests/" + sessionId + "/object");
    String requestObject = OpenIdFixtures.requestObject(client, sessionId);
    // The wallet verifies the request object against the verifier JWKS.
    String jwks = OpenIdFixtures.verifierJwks(client);
    String keyJson =
        mapper.writeValueAsString(mapper.readTree(jwks).get("keys").get(0));
    ECKey verifier = (ECKey) ECKey.parse(keyJson);
    SignedJWT parsed = SignedJWT.parse(requestObject);
    assertThat(parsed.verify(new ECDSAVerifier(verifier))).isTrue();
    assertThat(parsed.getHeader().getAlgorithm().getName()).isEqualTo("ES256");
    Map<String, Object> claims =
        mapper.convertValue(
            mapper.readTree(parsed.getPayload().toString()), Map.class);
    assertThat(claims.get("client_id")).isEqualTo(ConsentFixtures.AUDIENCE);
    assertThat(claims.get("response_type")).isEqualTo("vp_token");
    assertThat(claims.get("response_mode")).isEqualTo("direct_post.jwt");
    assertThat(claims.get("state")).isEqualTo(sessionId);
    assertThat(claims.get("dcql_query")).isNotNull();
    return new SessionView(sessionId, claims, keyJson);
  }

  private String walletResponse(SessionView session, Stage stage, String nonceOverride)
      throws Exception {
    String artifact = OpenIdFixtures.storedArtifact(owner, stage.credentialId());
    String nonce = nonceOverride != null ? nonceOverride : session.request().get("nonce").toString();
    String audience = session.request().get("client_id").toString();
    String kb = NimbusWallet.keyBinding(stage.holder(), audience, nonce, artifact, mapper);
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("vp_token", artifact + "~" + kb);
    body.put("presentation_submission", Dcql.submission());
    body.put("state", session.sessionId());
    return NimbusWallet.encryptResponse(
        session.verifierJwk(), mapper.writeValueAsString(body));
  }

  @Test
  void encryptedResponseCircleAccepts() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "vp-ok");
    SessionView session = openSession(stage);
    Map<String, Object> decided =
        OpenIdFixtures.vpRespondForm(client, session.sessionId(), walletResponse(session, stage, null));
    assertThat(decided.get("outcome")).isEqualTo("ACCEPTED");
    assertThat(decided.get("reasonCode")).isEqualTo("OK");
    assertThat(decided.get("profile")).isEqualTo(VerificationService.SDJWT_VC_PROFILE);
    String state = owner.queryForObject(
        "SELECT state FROM vp_session WHERE id = ?", String.class, UUID.fromString(session.sessionId()));
    assertThat(state).isEqualTo("COMPLETED");
    // The receipt reads back through the native decision API.
    Map<String, Object> retrieved = VerificationFixtures.decision(
        client, stage.rp(), decided.get("decisionId").toString());
    assertThat(retrieved.get("outcome")).isEqualTo("ACCEPTED");
  }

  @Test
  void responseReplaysByteIdentically() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "vp-replay");
    SessionView session = openSession(stage);
    String jwe = walletResponse(session, stage, null);
    Map<String, Object> first = OpenIdFixtures.vpRespondForm(client, session.sessionId(), jwe);
    // Same JWE bytes again: the stored decision replays verbatim.
    Map<String, Object> second = OpenIdFixtures.vpRespondForm(client, session.sessionId(), jwe);
    assertThat(second).isEqualTo(first);
    Integer count = owner.queryForObject(
        "SELECT COUNT(*) FROM verification_decision WHERE request_id = ?",
        Integer.class, UUID.fromString(stage.requestId()));
    assertThat(count).isEqualTo(1);
  }

  @Test
  void wrongKbNonceRejectsBinding() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "vp-nonce");
    SessionView session = openSession(stage);
    Map<String, Object> decided = OpenIdFixtures.vpRespondForm(
        client, session.sessionId(), walletResponse(session, stage, "wrong-nonce-00000001"));
    assertThat(decided.get("outcome")).isEqualTo("REJECTED");
    assertThat(decided.get("reasonCode")).isEqualTo("BINDING_INVALID");
  }

  @Test
  void pendingConsentRejectsWithoutDecisionBypass() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "vp-pend-issuer", Set.of("ISSUER_OPS"));
    TestAccount rp = TestAccounts.createInTenant(
        owner, issuer.tenantId(), "vp-pend-rp", Set.of("RP_CLIENT"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String credentialId = ConsentFixtures.issueCredential(client, issuer, holder, mapper);
    Map<String, Object> created = ConsentFixtures.create(
        client, rp, ConsentFixtures.createBody(UUID.fromString(credentialId)));
    String requestId = created.get("requestId").toString();
    // No holder decision: the VP session still opens, but no
    // presentation can be accepted behind it.
    Map<String, Object> session = OpenIdFixtures.vpRequest(client, rp, requestId);
    String sessionId = session.get("session_id").toString();
    String requestObject = OpenIdFixtures.requestObject(client, sessionId);
    var claims = mapper.readTree(
        SignedJWT.parse(requestObject).getPayload().toString());
    String artifact = OpenIdFixtures.storedArtifact(owner, credentialId);
    String kb = NimbusWallet.keyBinding(
        holder, claims.get("client_id").asString(), claims.get("nonce").asString(),
        artifact, mapper);
    String jwks = OpenIdFixtures.verifierJwks(client);
    String keyJson =
        mapper.writeValueAsString(mapper.readTree(jwks).get("keys").get(0));
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("vp_token", artifact + "~" + kb);
    body.put("presentation_submission", Dcql.submission());
    body.put("state", sessionId);
    Map<String, Object> decided = OpenIdFixtures.vpRespondForm(
        client, sessionId,
        NimbusWallet.encryptResponse(keyJson, mapper.writeValueAsString(body)));
    assertThat(decided.get("outcome")).isEqualTo("REJECTED");
    assertThat(decided.get("reasonCode")).isEqualTo("CONSENT_NOT_APPROVED");
  }

  @Test
  void plainDirectPostIsRejected() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "vp-plain");
    SessionView session = openSession(stage);
    String artifact = OpenIdFixtures.storedArtifact(owner, stage.credentialId());
    String kb = NimbusWallet.keyBinding(
        stage.holder(), ConsentFixtures.AUDIENCE,
        session.request().get("nonce").toString(), artifact, mapper);
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/vp/responses/" + session.sessionId())
                    .contentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED)
                    .body(
                        "vp_token="
                            + java.net.URLEncoder.encode(
                                artifact + "~" + kb, java.nio.charset.StandardCharsets.UTF_8)
                            + "&presentation_submission="
                            + java.net.URLEncoder.encode(
                                mapper.writeValueAsString(Dcql.submission()),
                                java.nio.charset.StandardCharsets.UTF_8))
                    .retrieve()
                    .body(String.class))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_request");
  }

  @Test
  void tamperedJweRejects() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "vp-tamp");
    SessionView session = openSession(stage);
    String jwe = walletResponse(session, stage, null);
    int dot = jwe.indexOf('.');
    char replacement = jwe.charAt(dot + 4) == 'A' ? 'B' : 'A';
    String tampered = jwe.substring(0, dot + 4) + replacement + jwe.substring(dot + 5);
    assertThatThrownBy(
            () -> OpenIdFixtures.vpRespondForm(client, session.sessionId(), tampered))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void wrongStateRejects() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "vp-state");
    SessionView session = openSession(stage);
    String artifact = OpenIdFixtures.storedArtifact(owner, stage.credentialId());
    String kb = NimbusWallet.keyBinding(
        stage.holder(), ConsentFixtures.AUDIENCE,
        session.request().get("nonce").toString(), artifact, mapper);
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("vp_token", artifact + "~" + kb);
    body.put("presentation_submission", Dcql.submission());
    body.put("state", UUID.randomUUID().toString());
    String jwe = NimbusWallet.encryptResponse(
        session.verifierJwk(), mapper.writeValueAsString(body));
    assertThatThrownBy(
            () -> OpenIdFixtures.vpRespondForm(client, session.sessionId(), jwe))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_request");
  }

  @Test
  void expiredSessionRejects() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "vp-exp");
    SessionView session = openSession(stage);
    owner.update(
        "UPDATE vp_session SET expires_at = now() - INTERVAL '1 minute' WHERE id = ?",
        UUID.fromString(session.sessionId()));
    assertThatThrownBy(
            () -> OpenIdFixtures.vpRespondForm(
                client, session.sessionId(), walletResponse(session, stage, null)))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_request");
    String state = owner.queryForObject(
        "SELECT state FROM vp_session WHERE id = ?", String.class,
        UUID.fromString(session.sessionId()));
    assertThat(state).isEqualTo("EXPIRED");
  }

  @Test
  void unknownSessionIsNotFound() {
    assertThatThrownBy(
            () -> OpenIdFixtures.requestObject(client, UUID.randomUUID().toString()))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
  }

  @Test
  void sessionCreationRequiresRpClient() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "vp-rbac");
    assertThatThrownBy(
            () -> OpenIdFixtures.vpRequest(client, stage.holderAgent(), stage.requestId()))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
  }
}
