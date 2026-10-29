package dev.sovra.issuance;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.util.Base64URL;
import dev.sovra.SovraAppRoleBase;
import dev.sovra.consent.ConsentFixtures;
import dev.sovra.trust.TrustService;
import dev.sovra.verification.VerificationFixtures;
import dev.sovra.verification.VerificationService;
import id.walt.sdjwt.SDJwt;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * SOV-036 profile qualification over HTTP: with
 * {@code sovra.profile=sdjwt-vc} the service issues real SD-JWT VC
 * artifacts and the consent-to-verification flow accepts them. This
 * boots a second application context on the shared test database;
 * tags keep its fixtures disjoint from the synthetic context.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = "sovra.profile=sdjwt-vc")
class WaltProfileIssuanceTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  @Autowired TrustService trust;

  @Autowired CredentialEncoder encoder;

  @Autowired ObjectMapper mapper;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() throws Exception {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
    IssuanceFixtures.ensureSyntheticIssuer(owner, trust, mapper);
  }

  @Test
  void waltProfileWiresSdJwtEncoder() {
    assertThat(encoder).isInstanceOf(WaltIdSdJwtVcEncoder.class);
  }

  @Test
  void issuanceMintsSdJwtVcArtifact() throws Exception {
    VerificationFixtures.Stage stage =
        VerificationFixtures.approvedStage(client, owner, mapper, "wprof-mint");
    String artifact = owner.queryForObject(
        "SELECT artifact FROM credential_artifact WHERE id = ?", String.class,
        UUID.fromString(stage.credentialId()));
    assertThat(artifact).isNotNull().contains("~");

    // Independent shape check: issuer-signed JWT head with the SD-JWT
    // VC media type, plus disclosures — not the synthetic JWT.
    String head = artifact.substring(0, artifact.indexOf('~'));
    String headerJson = new String(
        Base64URL.from(head.split("\\.")[0]).decode(), StandardCharsets.UTF_8);
    assertThat(mapper.readTree(headerJson).get("typ").asString()).isEqualTo("dc+sd-jwt");
    SDJwt parsed = SDJwt.Companion.parse(artifact);
    assertThat(parsed.getDisclosures()).isNotEmpty();
    String resolved = parsed.getSdPayload().getFullPayload().toString();
    assertThat(mapper.readTree(resolved).get("vct").asString())
        .isEqualTo(IssuanceFixtures.ADULT_VCT);
  }

  @Test
  void consentToVerificationAcceptsUnderWaltProfile() throws Exception {
    VerificationFixtures.Stage stage =
        VerificationFixtures.approvedStage(client, owner, mapper, "wprof-e2e");
    Map<String, Object> decided = VerificationFixtures.verify(client, stage.rp(),
        dev.sovra.openid.OpenIdFixtures.kbVerifyBody(owner, stage.holder(),
            stage.credentialId(), stage.requestId(), VerificationFixtures.nonce(),
            ConsentFixtures.AUDIENCE, mapper));
    assertThat(decided.get("outcome")).isEqualTo("ACCEPTED");
    assertThat(decided.get("reasonCode")).isEqualTo("OK");
    assertThat(decided.get("profile")).isEqualTo(VerificationService.SDJWT_VC_PROFILE);
    assertThat(decided.get("synthetic")).isEqualTo(Boolean.TRUE);

    Map<String, Object> retrieved = VerificationFixtures.decision(
        client, stage.rp(), decided.get("decisionId").toString());
    assertThat(retrieved.get("profile")).isEqualTo(VerificationService.SDJWT_VC_PROFILE);
  }

  @Test
  void tamperedSdJwtRejectedUnderWaltProfile() throws Exception {
    VerificationFixtures.Stage stage =
        VerificationFixtures.approvedStage(client, owner, mapper, "wprof-tamp");
    String stored = owner.queryForObject(
        "SELECT artifact FROM credential_artifact WHERE id = ?", String.class,
        UUID.fromString(stage.credentialId()));
    assertThat(stored).isNotNull();
    int dot = stored.indexOf('.');
    char replacement = stored.charAt(dot + 4) == 'A' ? 'B' : 'A';
    owner.update("UPDATE credential_artifact SET artifact = ? WHERE id = ?",
        stored.substring(0, dot + 4) + replacement + stored.substring(dot + 5),
        UUID.fromString(stage.credentialId()));
    Map<String, Object> decided = VerificationFixtures.verify(client, stage.rp(),
        dev.sovra.openid.OpenIdFixtures.kbVerifyBody(owner, stage.holder(),
            stage.credentialId(), stage.requestId(), VerificationFixtures.nonce(),
            ConsentFixtures.AUDIENCE, mapper));
    assertThat(decided.get("outcome")).isEqualTo("REJECTED");
    assertThat(decided.get("reasonCode")).isEqualTo("ARTIFACT_SIGNATURE_INVALID");
  }
}
