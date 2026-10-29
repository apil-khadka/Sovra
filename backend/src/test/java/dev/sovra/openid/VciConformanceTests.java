package dev.sovra.openid;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * SOV-036 VCI adversarial corpus: grant confusion, proof forgery and
 * replay, downgrade attempts, expiry, and token abuse. Every case must
 * fail closed with an OAuth2 error code and issue nothing.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = "sovra.profile=sdjwt-vc")
class VciConformanceTests extends SovraAppRoleBase {

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

  private record Desk(TestAccount issuer, TestAccount holderAgent) {}

  private Desk desk(String tag) {
    TestAccount issuer = TestAccounts.create(owner, tag + "-issuer", Set.of("ISSUER_OPS"));
    TestAccount holderAgent = TestAccounts.createInTenant(
        owner, issuer.tenantId(), tag + "-agent", Set.of("TENANT_MEMBER"));
    return new Desk(issuer, holderAgent);
  }

  private String offerCode(Desk desk) {
    return preAuthCode(OpenIdFixtures.offer(
        client, desk.issuer(), IssuanceFixtures.ISSUER_ID, IssuanceFixtures.ADULT_VCT));
  }

  @SuppressWarnings("unchecked")
  private static String preAuthCode(Map<String, Object> offered) {
    Map<String, Object> offer = (Map<String, Object>) offered.get("credential_offer");
    Map<String, Object> grants = (Map<String, Object>) offer.get("grants");
    return (String) ((Map<String, Object>) grants.get("pre-authorized_code"))
        .get("pre-authorized_code");
  }

  private Map<String, Object> tokenFor(Desk desk, IssuanceFixtures.HolderKeys holder)
      throws Exception {
    return OpenIdFixtures.tokenPreAuth(client, offerCode(desk));
  }

  private String credentialRaw(String accessToken, Map<String, Object> body) {
    return client
        .post()
        .uri("/api/vci/credential")
        .header("Authorization", "Bearer " + accessToken)
        .contentType(MediaType.APPLICATION_JSON)
        .body(body)
        .retrieve()
        .body(String.class);
  }

  private Map<String, Object> credentialBody(String configurationId, String format, Object proof) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("format", format);
    body.put("credential_configuration_id", configurationId);
    body.put("proof", proof);
    return body;
  }

  private long credentialCount(UUID tenantId) {
    return owner.queryForObject(
        "SELECT COUNT(*) FROM credential_artifact WHERE tenant_id = ?", Long.class, tenantId);
  }

  @Test
  void grantTypeConfusionRejects() throws Exception {
    Desk desk = desk("vcic-gconf");
    String verifier = "verifier-verifier-verifier-verifier-0001";
    Map<String, Object> granted = OpenIdFixtures.authorize(
        client, desk.holderAgent(), IssuanceFixtures.ISSUER_ID, IssuanceFixtures.ADULT_VCT,
        NimbusWallet.pkceChallenge(verifier));
    // Authorization code through the pre-authorized grant: refused.
    assertThatThrownBy(
            () -> OpenIdFixtures.tokenPreAuth(client, granted.get("code").toString()))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_grant");
    // Pre-authorized code through the authorization-code grant: refused.
    assertThatThrownBy(
            () -> OpenIdFixtures.tokenCode(client, offerCode(desk), verifier))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_grant");
  }

  @Test
  void expiredGrantRejects() {
    Desk desk = desk("vcic-exp");
    String code = offerCode(desk);
    owner.update(
        "UPDATE vci_grant SET expires_at = now() - INTERVAL '1 minute'"
            + " WHERE tenant_id = ? AND consumed_at IS NULL",
        desk.issuer().tenantId());
    assertThatThrownBy(() -> OpenIdFixtures.tokenPreAuth(client, code))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_grant");
  }

  @Test
  void proofWithWrongAudienceRejects() throws Exception {
    Desk desk = desk("vcic-aud");
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    Map<String, Object> token = tokenFor(desk, holder);
    long before = credentialCount(desk.issuer().tenantId());
    String proof = NimbusWallet.vciProof(
        holder, "https://evil.example/issuers/1", token.get("c_nonce").toString(), mapper);
    assertThatThrownBy(() -> OpenIdFixtures.credential(
            client, token.get("access_token").toString(), VciService.CONFIGURATION_ID, proof))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_proof");
    assertThat(credentialCount(desk.issuer().tenantId())).isEqualTo(before);
  }

  @Test
  void proofWithoutEmbeddedKeyRejects() throws Exception {
    Desk desk = desk("vcic-nojwk");
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    Map<String, Object> token = tokenFor(desk, holder);
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("aud", IssuanceFixtures.ISSUER_ID);
    claims.put("iat", java.time.Instant.now().getEpochSecond());
    claims.put("nonce", token.get("c_nonce").toString());
    String proof = NimbusWallet.signCompact(
        holder, "{\"alg\":\"ES256\",\"typ\":\"openid4vci-proof+jwt\"}",
        mapper.writeValueAsString(claims));
    assertThatThrownBy(() -> OpenIdFixtures.credential(
            client, token.get("access_token").toString(), VciService.CONFIGURATION_ID, proof))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_proof");
  }

  @Test
  void downgradeProofAlgorithmRejects() throws Exception {
    Desk desk = desk("vcic-alg");
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    Map<String, Object> token = tokenFor(desk, holder);
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("aud", IssuanceFixtures.ISSUER_ID);
    claims.put("iat", java.time.Instant.now().getEpochSecond());
    claims.put("nonce", token.get("c_nonce").toString());
    Map<String, Object> header = new LinkedHashMap<>();
    header.put("alg", "RS256");
    header.put("typ", "openid4vci-proof+jwt");
    header.put("jwk", mapper.convertValue(holder.jwk(), Map.class));
    // Genuine RS256 shape is unnecessary: the pinned ES256 gate fires first.
    String proof = NimbusWallet.signCompact(
        holder, mapper.writeValueAsString(header), mapper.writeValueAsString(claims));
    assertThatThrownBy(() -> OpenIdFixtures.credential(
            client, token.get("access_token").toString(), VciService.CONFIGURATION_ID, proof))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_proof");
  }

  @Test
  void proofReplayAfterRotationRejects() throws Exception {
    Desk desk = desk("vcic-replay");
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    Map<String, Object> token = tokenFor(desk, holder);
    String accessToken = token.get("access_token").toString();
    String proof = NimbusWallet.vciProof(
        holder, IssuanceFixtures.ISSUER_ID, token.get("c_nonce").toString(), mapper);
    // Rotate first: the captured proof now names a dead nonce.
    client
        .post()
        .uri("/api/vci/nonce")
        .header("Authorization", "Bearer " + accessToken)
        .retrieve()
        .body(String.class);
    assertThatThrownBy(() -> OpenIdFixtures.credential(
            client, accessToken, VciService.CONFIGURATION_ID, proof))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_proof");
  }

  @Test
  void keyConfusedProofRejects() throws Exception {
    Desk desk = desk("vcic-keyconf");
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    IssuanceFixtures.HolderKeys attacker = IssuanceFixtures.generateHolder(mapper);
    Map<String, Object> token = tokenFor(desk, holder);
    Map<String, Object> header = new LinkedHashMap<>();
    header.put("alg", "ES256");
    header.put("typ", "openid4vci-proof+jwt");
    header.put("jwk", mapper.convertValue(holder.jwk(), Map.class));
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("aud", IssuanceFixtures.ISSUER_ID);
    claims.put("iat", java.time.Instant.now().getEpochSecond());
    claims.put("nonce", token.get("c_nonce").toString());
    // Victim key in the header, attacker signature: must not verify.
    String proof = NimbusWallet.signCompact(
        attacker, mapper.writeValueAsString(header), mapper.writeValueAsString(claims));
    assertThatThrownBy(() -> OpenIdFixtures.credential(
            client, token.get("access_token").toString(), VciService.CONFIGURATION_ID, proof))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_proof");
  }

  @Test
  void unknownConfigurationRejects() throws Exception {
    Desk desk = desk("vcic-config");
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    Map<String, Object> token = tokenFor(desk, holder);
    String proof = NimbusWallet.vciProof(
        holder, IssuanceFixtures.ISSUER_ID, token.get("c_nonce").toString(), mapper);
    assertThatThrownBy(() -> credentialRaw(
            token.get("access_token").toString(),
            credentialBody("other-config", "dc+sd-jwt",
                Map.of("proof_type", "jwt", "jwt", proof))))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_credential_request");
  }

  @Test
  void outOfProfileFormatRejects() throws Exception {
    Desk desk = desk("vcic-format");
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    Map<String, Object> token = tokenFor(desk, holder);
    String proof = NimbusWallet.vciProof(
        holder, IssuanceFixtures.ISSUER_ID, token.get("c_nonce").toString(), mapper);
    assertThatThrownBy(() -> credentialRaw(
            token.get("access_token").toString(),
            credentialBody(VciService.CONFIGURATION_ID, "jwt_vc_json-ld",
                Map.of("proof_type", "jwt", "jwt", proof))))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_credential_request");
  }

  @Test
  void batchRequestRejects() throws Exception {
    Desk desk = desk("vcic-batch");
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    Map<String, Object> token = tokenFor(desk, holder);
    String proof = NimbusWallet.vciProof(
        holder, IssuanceFixtures.ISSUER_ID, token.get("c_nonce").toString(), mapper);
    Map<String, Object> body =
        credentialBody(VciService.CONFIGURATION_ID, "dc+sd-jwt",
            Map.of("proof_type", "jwt", "jwt", proof));
    body.put("credential_requests", java.util.List.of(Map.of()));
    assertThatThrownBy(
            () -> credentialRaw(token.get("access_token").toString(), body))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_credential_request");
  }

  @Test
  void unknownProofTypeRejects() throws Exception {
    Desk desk = desk("vcic-ptype");
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    Map<String, Object> token = tokenFor(desk, holder);
    String proof = NimbusWallet.vciProof(
        holder, IssuanceFixtures.ISSUER_ID, token.get("c_nonce").toString(), mapper);
    assertThatThrownBy(() -> credentialRaw(
            token.get("access_token").toString(),
            credentialBody(VciService.CONFIGURATION_ID, "dc+sd-jwt",
                Map.of("proof_type", "ldp_vp", "jwt", proof))))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_proof");
  }

  @Test
  void unknownTokenRejects() {
    assertThatThrownBy(() -> credentialRaw(
            "no-such-token",
            credentialBody(VciService.CONFIGURATION_ID, "dc+sd-jwt",
                Map.of("proof_type", "jwt", "jwt", "x.y.z"))))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_token");
  }

  @Test
  void missingBearerRejects() {
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/vci/credential")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(
                        credentialBody(VciService.CONFIGURATION_ID, "dc+sd-jwt",
                            Map.of("proof_type", "jwt", "jwt", "x.y.z")))
                    .retrieve()
                    .body(String.class))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_token");
  }

  @Test
  void redemptionIsAuditedAsWalletCall() throws Exception {
    Desk desk = desk("vcic-audit");
    String code = offerCode(desk);
    OpenIdFixtures.tokenPreAuth(client, code);
    Map<String, Object> row = owner.queryForMap(
        "SELECT actor_type, action, decision FROM audit_event"
            + " WHERE tenant_id = ? AND action IN ('VCI_CREATE_OFFER', 'VCI_AUTHORIZE')"
            + " ORDER BY occurred_at DESC LIMIT 1",
        desk.issuer().tenantId());
    // The latest row is the wallet redemption (the offer row precedes it).
    assertThat(row.get("actor_type")).isEqualTo("openid-wallet");
    assertThat(row.get("decision")).isEqualTo("PERMIT");
  }
}
