package dev.sovra.openid;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.consent.ConsentFixtures;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import dev.sovra.verification.VerificationFixtures;
import dev.sovra.verification.VerificationService;
import id.walt.sdjwt.SDJwt;
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
 * SOV-036 OpenID4VCI flows over HTTP: credential-issuer metadata, the
 * pre-authorized_code grant, the authorization_code grant against the
 * synthetic AS (PKCE S256), single-use {@code c_nonce} proofs, and the
 * full circle from a VCI-issued credential to an ACCEPTED decision.
 * The wallet side is {@link NimbusWallet} throughout.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = "sovra.profile=sdjwt-vc")
class VciFlowTests extends SovraAppRoleBase {

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

  private record Desk(TestAccount issuer, TestAccount holderAgent, TestAccount rp) {}

  private Desk desk(String tag) {
    TestAccount issuer = TestAccounts.create(owner, tag + "-issuer", Set.of("ISSUER_OPS"));
    TestAccount holderAgent = TestAccounts.createInTenant(
        owner, issuer.tenantId(), tag + "-agent", Set.of("TENANT_MEMBER"));
    TestAccount rp = TestAccounts.createInTenant(
        owner, issuer.tenantId(), tag + "-rp", Set.of("RP_CLIENT"));
    return new Desk(issuer, holderAgent, rp);
  }

  @Test
  @SuppressWarnings("unchecked")
  void issuerMetadataIsPublic() {
    Map<String, Object> metadata =
        client.get().uri("/.well-known/openid-credential-issuer").retrieve().body(Map.class);
    assertThat(metadata).isNotNull();
    assertThat(metadata.get("credential_issuer"))
        .isEqualTo(IssuanceFixtures.ISSUER_ID);
    assertThat(metadata.get("token_endpoint").toString()).endsWith("/api/vci/token");
    assertThat(metadata.get("credential_endpoint").toString()).endsWith("/api/vci/credential");
    assertThat(metadata.get("nonce_endpoint").toString()).endsWith("/api/vci/nonce");
    Map<String, Object> configurations =
        (Map<String, Object>) metadata.get("credential_configurations_supported");
    assertThat(configurations).containsKey(VciService.CONFIGURATION_ID);
    Map<String, Object> configuration =
        (Map<String, Object>) configurations.get(VciService.CONFIGURATION_ID);
    assertThat(configuration.get("format")).isEqualTo("dc+sd-jwt");
    assertThat(configuration.get("vct")).isEqualTo(IssuanceFixtures.ADULT_VCT);
  }

  @Test
  @SuppressWarnings("unchecked")
  void offerNamesCredentialIssuerIdentifier() {
    Desk desk = desk("vci-offeriss");
    Map<String, Object> metadata =
        client.get().uri("/.well-known/openid-credential-issuer").retrieve().body(Map.class);
    Map<String, Object> offered = OpenIdFixtures.offer(
        client, desk.issuer(), IssuanceFixtures.ISSUER_ID, IssuanceFixtures.ADULT_VCT);
    Map<String, Object> offer = (Map<String, Object>) offered.get("credential_offer");
    assertThat(offer.get("credential_issuer")).isEqualTo(IssuanceFixtures.ISSUER_ID);
    assertThat(offer.get("credential_issuer")).isEqualTo(metadata.get("credential_issuer"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void preAuthorizedFlowIssuesVerifiableCredential() throws Exception {
    Desk desk = desk("vci-pre");
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    Map<String, Object> offered = OpenIdFixtures.offer(
        client, desk.issuer(), IssuanceFixtures.ISSUER_ID, IssuanceFixtures.ADULT_VCT);
    Map<String, Object> offer = (Map<String, Object>) offered.get("credential_offer");
    assertThat(offered.get("credential_offer_uri").toString())
        .startsWith("openid-credential-offer://");
    assertThat(((Map<String, Object>) offer.get("grants"))).containsKey("pre-authorized_code");
    String code = (String) ((Map<String, Object>) ((Map<String, Object>) offer.get("grants"))
        .get("pre-authorized_code")).get("pre-authorized_code");

    Map<String, Object> token = OpenIdFixtures.tokenPreAuth(client, code);
    assertThat(token.get("token_type")).isEqualTo("Bearer");
    assertThat(token.get("access_token")).isNotNull();
    assertThat(token.get("c_nonce")).isNotNull();

    String proof = NimbusWallet.vciProof(
        holder, IssuanceFixtures.ISSUER_ID, token.get("c_nonce").toString(), mapper);
    Map<String, Object> issued = OpenIdFixtures.credential(
        client, token.get("access_token").toString(), VciService.CONFIGURATION_ID, proof);
    String artifact = (String) ((Map<String, Object>)
        ((java.util.List<Object>) issued.get("credentials")).get(0)).get("credential");
    assertThat(artifact).contains("~");
    SDJwt parsed = SDJwt.Companion.parse(artifact);
    assertThat(mapper.readTree(parsed.getFullPayload().toString()).get("vct").asString())
        .isEqualTo(IssuanceFixtures.ADULT_VCT);

    // The VCI credential completes the consent-to-verification circle.
    String credentialId =
        mapper.readTree(parsed.getFullPayload().toString()).get("jti").asString();
    Map<String, Object> created = ConsentFixtures.create(
        client, desk.rp(), ConsentFixtures.createBody(UUID.fromString(credentialId)));
    String requestId = created.get("requestId").toString();
    Map<String, Object> review = ConsentFixtures.review(client, desk.rp(), requestId);
    ConsentFixtures.decide(client, desk.holderAgent(), requestId,
        ConsentFixtures.decideBody(holder, review, "approve", mapper));
    Map<String, Object> decided = VerificationFixtures.verify(client, desk.rp(),
        OpenIdFixtures.kbVerifyBody(owner, holder, credentialId, requestId,
            VerificationFixtures.nonce(), ConsentFixtures.AUDIENCE, mapper));
    assertThat(decided.get("outcome")).isEqualTo("ACCEPTED");
    assertThat(decided.get("profile")).isEqualTo(VerificationService.SDJWT_VC_PROFILE);
  }

  @Test
  @SuppressWarnings("unchecked")
  void authorizationCodeFlowIssuesVerifiableCredential() throws Exception {
    Desk desk = desk("vci-code");
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String verifier = OpenIdFixtures.nonce() + OpenIdFixtures.nonce();
    String challenge = NimbusWallet.pkceChallenge(verifier);
    Map<String, Object> granted = OpenIdFixtures.authorize(
        client, desk.holderAgent(), IssuanceFixtures.ISSUER_ID, IssuanceFixtures.ADULT_VCT,
        challenge);
    String code = granted.get("code").toString();

    Map<String, Object> token = OpenIdFixtures.tokenCode(client, code, verifier);
    assertThat(token.get("access_token")).isNotNull();
    String proof = NimbusWallet.vciProof(
        holder, IssuanceFixtures.ISSUER_ID, token.get("c_nonce").toString(), mapper);
    Map<String, Object> issued = OpenIdFixtures.credential(
        client, token.get("access_token").toString(), VciService.CONFIGURATION_ID, proof);
    String artifact = (String) ((Map<String, Object>)
        ((java.util.List<Object>) issued.get("credentials")).get(0)).get("credential");
    assertThat(artifact).contains("~");
    assertThat(SDJwt.Companion.parse(artifact).getDisclosures()).isNotEmpty();
  }

  @Test
  void preAuthorizedCodeIsSingleUse() {
    Desk desk = desk("vci-once");
    Map<String, Object> offered = OpenIdFixtures.offer(
        client, desk.issuer(), IssuanceFixtures.ISSUER_ID, IssuanceFixtures.ADULT_VCT);
    String code = preAuthCode(offered);
    assertThat(OpenIdFixtures.tokenPreAuth(client, code).get("access_token")).isNotNull();
    assertThatThrownBy(() -> OpenIdFixtures.tokenPreAuth(client, code))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_grant");
  }

  @Test
  void wrongPkceVerifierRejects() throws Exception {
    Desk desk = desk("vci-pkce");
    Map<String, Object> granted = OpenIdFixtures.authorize(
        client, desk.holderAgent(), IssuanceFixtures.ISSUER_ID, IssuanceFixtures.ADULT_VCT,
        NimbusWallet.pkceChallenge("correct-verifier-correct-verifier-correct-01"));
    assertThatThrownBy(() -> OpenIdFixtures.tokenCode(
            client, granted.get("code").toString(), "wrong-verifier-wrong-verifier-wrong-1234"))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_grant");
  }

  @Test
  void unknownCodeRejectsWithoutOracleDetail() {
    assertThatThrownBy(() -> OpenIdFixtures.tokenPreAuth(client, "no-such-code"))
        .isInstanceOf(HttpClientErrorException.BadRequest.class)
        .hasMessageContaining("invalid_grant");
  }

  @Test
  void failedProofKeepsTokenAliveAfterNonceRotation() throws Exception {
    Desk desk = desk("vci-retry");
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    Map<String, Object> token =
        OpenIdFixtures.tokenPreAuth(client, preAuthCode(OpenIdFixtures.offer(
            client, desk.issuer(), IssuanceFixtures.ISSUER_ID, IssuanceFixtures.ADULT_VCT)));
    String accessToken = token.get("access_token").toString();
    // Proof bound to a stale nonce: consumed, issuance refused.
    String badProof = NimbusWallet.vciProof(
        holder, IssuanceFixtures.ISSUER_ID, "stale-nonce", mapper);
    assertThatThrownBy(() -> OpenIdFixtures.credential(
            client, accessToken, VciService.CONFIGURATION_ID, badProof))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    // Fresh nonce, correct proof: the same token still issues once.
    Map<String, Object> rotated = rotateNonce(accessToken);
    String goodProof = NimbusWallet.vciProof(
        holder, IssuanceFixtures.ISSUER_ID, rotated.get("c_nonce").toString(), mapper);
    Map<String, Object> issued = OpenIdFixtures.credential(
        client, accessToken, VciService.CONFIGURATION_ID, goodProof);
    assertThat(issued.get("credentials")).isNotNull();
    // The token is spent: no second credential.
    Map<String, Object> rotatedAgain = rotateNonceOrNull(accessToken);
    assertThat(rotatedAgain).isNull();
  }

  @Test
  void unknownConfigurationRejects() {
    Desk desk = desk("vci-unknown");
    assertThatThrownBy(() -> OpenIdFixtures.offer(
            client, desk.issuer(), "https://sovra.example/issuers/other", "https://x.example/vct"))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void offerRequiresIssuerOps() {
    Desk desk = desk("vci-rbac");
    assertThatThrownBy(() -> OpenIdFixtures.offer(
            client, desk.rp(), IssuanceFixtures.ISSUER_ID, IssuanceFixtures.ADULT_VCT))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(() -> OpenIdFixtures.authorize(
            client, desk.issuer(), IssuanceFixtures.ISSUER_ID, IssuanceFixtures.ADULT_VCT,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn0123456789-_"))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
  }

  @SuppressWarnings("unchecked")
  private static String preAuthCode(Map<String, Object> offered) {
    Map<String, Object> offer = (Map<String, Object>) offered.get("credential_offer");
    Map<String, Object> grants = (Map<String, Object>) offer.get("grants");
    return (String) ((Map<String, Object>) grants.get("pre-authorized_code"))
        .get("pre-authorized_code");
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> rotateNonce(String accessToken) {
    return client
        .post()
        .uri("/api/vci/nonce")
        .header("Authorization", "Bearer " + accessToken)
        .retrieve()
        .body(Map.class);
  }

  private Map<String, Object> rotateNonceOrNull(String accessToken) {
    try {
      return rotateNonce(accessToken);
    } catch (HttpClientErrorException.BadRequest e) {
      return null;
    }
  }
}
