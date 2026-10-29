package dev.sovra.openid;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import dev.sovra.SovraAppRoleBase;
import dev.sovra.consent.ConsentFixtures;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import dev.sovra.verification.VerificationFixtures;
import dev.sovra.verification.VerificationFixtures.Stage;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
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
 * SOV-036 VP adversarial corpus: JWE abuse, presentation forgery and
 * replay, foreign-issuer artifacts, and submission-shape attacks.
 * Transport forgeries fail closed at the VP layer; binding forgeries
 * become REJECTED decisions with reason codes, never acceptances.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = "sovra.profile=sdjwt-vc")
class VpConformanceTests extends SovraAppRoleBase {

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

  private record SessionView(String sessionId, String nonce, String verifierJwk) {}

  private SessionView openSession(Stage stage) throws Exception {
    Map<String, Object> created =
        OpenIdFixtures.vpRequest(client, stage.rp(), stage.requestId());
    String sessionId = created.get("session_id").toString();
    String requestObject = OpenIdFixtures.requestObject(client, sessionId);
    String nonce =
        mapper.readTree(SignedJWT.parse(requestObject).getPayload().toString())
            .get("nonce").asString();
    String jwks = OpenIdFixtures.verifierJwks(client);
    String keyJson =
        mapper.writeValueAsString(mapper.readTree(jwks).get("keys").get(0));
    return new SessionView(sessionId, nonce, keyJson);
  }

  private String respond(
      SessionView session, String vpToken, Map<String, Object> submission, String state)
      throws Exception {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("vp_token", vpToken);
    body.put("presentation_submission", submission);
    body.put("state", state);
    String jwe = NimbusWallet.encryptResponse(
        session.verifierJwk(), mapper.writeValueAsString(body));
    return respondJwe(session.sessionId(), jwe);
  }

  private String respondJwe(String sessionId, String jwe) {
    Map<String, Object> decided = OpenIdFixtures.vpRespondForm(client, sessionId, jwe);
    return decided.get("outcome") + "/" + decided.get("reasonCode");
  }

  private String kb(Stage stage, String nonce, String audience) throws Exception {
    return NimbusWallet.keyBinding(
        stage.holder(), audience, nonce,
        OpenIdFixtures.storedArtifact(owner, stage.credentialId()), mapper);
  }

  @Test
  void jweToWrongKeyRejects() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "vpc-wkey");
    SessionView session = openSession(stage);
    String artifact = OpenIdFixtures.storedArtifact(owner, stage.credentialId());
    String token = artifact + "~" + kb(stage, session.nonce(), ConsentFixtures.AUDIENCE);
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("vp_token", token);
    body.put("presentation_submission", Dcql.submission());
    body.put("state", session.sessionId());
    ECKey wrongKey = new ECKeyGenerator(Curve.P_256).keyID("wrong").generate();
    String jwe = NimbusWallet.encryptResponse(
        wrongKey.toJSONString(), mapper.writeValueAsString(body));
    assertThatThrownBy(() -> OpenIdFixtures.vpRespondForm(client, session.sessionId(), jwe))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void downgradedJweTransportRejects() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "vpc-downgrade");
    SessionView session = openSession(stage);
    String artifact = OpenIdFixtures.storedArtifact(owner, stage.credentialId());
    String token = artifact + "~" + kb(stage, session.nonce(), ConsentFixtures.AUDIENCE);
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("vp_token", token);
    body.put("presentation_submission", Dcql.submission());
    body.put("state", session.sessionId());
    // Well-formed and decryptable, but outside the frozen
    // ECDH-ES+A256KW/A256GCM transport: must still refuse.
    String jwe = NimbusWallet.encryptResponseWith(
        session.verifierJwk(), mapper.writeValueAsString(body),
        com.nimbusds.jose.JWEAlgorithm.ECDH_ES,
        com.nimbusds.jose.EncryptionMethod.A128GCM);
    assertThatThrownBy(() -> OpenIdFixtures.vpRespondForm(client, session.sessionId(), jwe))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void truncatedJweRejects() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "vpc-trunc");
    SessionView session = openSession(stage);
    assertThatThrownBy(
            () -> OpenIdFixtures.vpRespondForm(client, session.sessionId(), "a.b.c.d"))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void presentationWithoutBindingRejects() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "vpc-nokb");
    SessionView session = openSession(stage);
    String artifact = OpenIdFixtures.storedArtifact(owner, stage.credentialId());
    assertThatThrownBy(
            () ->
                respond(
                    session, artifact, Dcql.submission(), session.sessionId()))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void wrongKeyTypeBindingRejectsAsDecision() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "vpc-typ");
    SessionView session = openSession(stage);
    String artifact = OpenIdFixtures.storedArtifact(owner, stage.credentialId());
    // Same claims, wrong JOSE type: the delegation must refuse it.
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("aud", ConsentFixtures.AUDIENCE);
    claims.put("nonce", session.nonce());
    claims.put("sd_hash", "anything");
    claims.put("iat", Instant.now().getEpochSecond());
    String fakeKb = NimbusWallet.signCompact(
        stage.holder(), "{\"alg\":\"ES256\",\"typ\":\"jwt\"}",
        mapper.writeValueAsString(claims));
    assertThat(respond(session, artifact + "~" + fakeKb, Dcql.submission(), session.sessionId()))
        .isEqualTo("REJECTED/BINDING_INVALID");
  }

  @Test
  void tamperedSdHashRejectsAsDecision() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "vpc-hash");
    SessionView session = openSession(stage);
    String artifact = OpenIdFixtures.storedArtifact(owner, stage.credentialId());
    String goodKb = kb(stage, session.nonce(), ConsentFixtures.AUDIENCE);
    String[] parts = goodKb.split("\\.", -1);
    var payload = mapper.readTree(
        com.nimbusds.jose.util.Base64URL.from(parts[1]).decode());
    ((tools.jackson.databind.node.ObjectNode) payload).put("sd_hash",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    String tamperedPayload =
        com.nimbusds.jose.util.Base64URL.encode(
                mapper.writeValueAsString(payload).getBytes(java.nio.charset.StandardCharsets.UTF_8))
            .toString();
    // Re-sign over the tampered hash so only the binding check can fire.
    String resigned = NimbusWallet.signCompact(
        stage.holder(),
        new String(
            com.nimbusds.jose.util.Base64URL.from(parts[0]).decode(),
            java.nio.charset.StandardCharsets.UTF_8),
        new String(
            com.nimbusds.jose.util.Base64URL.from(tamperedPayload).decode(),
            java.nio.charset.StandardCharsets.UTF_8));
    assertThat(respond(session, artifact + "~" + resigned, Dcql.submission(), session.sessionId()))
        .isEqualTo("REJECTED/BINDING_INVALID");
  }

  @Test
  void audienceConfusedBindingRejectsAsDecision() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "vpc-aud");
    SessionView session = openSession(stage);
    String artifact = OpenIdFixtures.storedArtifact(owner, stage.credentialId());
    String confused = NimbusWallet.keyBinding(
        stage.holder(), "https://evil.example/cb", session.nonce(), artifact, mapper);
    assertThat(respond(session, artifact + "~" + confused, Dcql.submission(), session.sessionId()))
        .isEqualTo("REJECTED/BINDING_INVALID");
  }

  @Test
  void bindingReplayAcrossSessionsRejects() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "vpc-xreplay");
    SessionView first = openSession(stage);
    SessionView second = openSession(stage);
    String artifact = OpenIdFixtures.storedArtifact(owner, stage.credentialId());
    // KB captured for the first session's nonce, replayed into the second.
    String captured = NimbusWallet.keyBinding(
        stage.holder(), ConsentFixtures.AUDIENCE, first.nonce(), artifact, mapper);
    assertThat(respond(second, artifact + "~" + captured, Dcql.submission(), second.sessionId()))
        .isEqualTo("REJECTED/BINDING_INVALID");
  }

  @Test
  void submissionMismatchRejects() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "vpc-sub");
    SessionView session = openSession(stage);
    String artifact = OpenIdFixtures.storedArtifact(owner, stage.credentialId());
    String token = artifact + "~" + kb(stage, session.nonce(), ConsentFixtures.AUDIENCE);
    Map<String, Object> bad = new LinkedHashMap<>(Dcql.submission());
    bad.put("descriptor_map", java.util.List.of(
        Map.of("id", "other-claim", "format", "dc+sd-jwt", "path", "$")));
    assertThatThrownBy(() -> respond(session, token, bad, session.sessionId()))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void foreignPresentationIsNotTheConsentedCredential() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "vpc-foreign");
    SessionView session = openSession(stage);
    var foreign = NimbusWallet.fixedForeignIssuer(mapper);
    String presented = NimbusWallet.foreignCredential(
        stage.holder(), foreign, UUID.randomUUID().toString(), IssuanceFixtures.ADULT_VCT,
        Instant.now(), Instant.now().plusSeconds(3600), mapper);
    String kb = NimbusWallet.keyBinding(
        stage.holder(), ConsentFixtures.AUDIENCE, session.nonce(), presented, mapper);
    assertThatThrownBy(
            () -> respond(session, presented + "~" + kb, Dcql.submission(), session.sessionId()))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_request");
  }

  @Test
  void foreignStoredArtifactNeverVerifies() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "vpc-fstored");
    var foreign = NimbusWallet.fixedForeignIssuer(mapper);
    // Well-formed third-party bytes in the credential record: the
    // artifact gate must refuse them (their key is outside the trust
    // snapshot, and their issuer is not the recorded one).
    String foreignArtifact = NimbusWallet.foreignCredential(
        stage.holder(), foreign, stage.credentialId(), IssuanceFixtures.ADULT_VCT,
        Instant.now(), Instant.now().plusSeconds(3600), mapper);
    owner.update("UPDATE credential_artifact SET artifact = ? WHERE id = ?",
        foreignArtifact, UUID.fromString(stage.credentialId()));
    Map<String, Object> decided = VerificationFixtures.verify(client, stage.rp(),
        OpenIdFixtures.kbVerifyBody(owner, stage.holder(), stage.credentialId(),
            stage.requestId(), VerificationFixtures.nonce(), ConsentFixtures.AUDIENCE, mapper));
    assertThat(decided.get("outcome")).isEqualTo("REJECTED");
    assertThat(decided.get("reasonCode")).isEqualTo("ISSUER_KEY_INACTIVE");
  }

  @Test
  void tamperedDisclosurePresentationRejects() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "vpc-disc");
    SessionView session = openSession(stage);
    String artifact = OpenIdFixtures.storedArtifact(owner, stage.credentialId());
    int tilde = artifact.indexOf('~');
    String tampered =
        artifact.substring(0, tilde + 1) + "A" + artifact.substring(tilde + 2);
    String kb = NimbusWallet.keyBinding(
        stage.holder(), ConsentFixtures.AUDIENCE, session.nonce(), tampered, mapper);
    assertThatThrownBy(
            () -> respond(session, tampered + "~" + kb, Dcql.submission(), session.sessionId()))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_request");
  }
}
