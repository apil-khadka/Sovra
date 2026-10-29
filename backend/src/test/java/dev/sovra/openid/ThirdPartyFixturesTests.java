package dev.sovra.openid;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import dev.sovra.issuance.IssuanceFixtures;
import id.walt.sdjwt.SDJwt;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

/**
 * SOV-036 third-party fixture qualification: the checked-in external
 * issuer key matches the minting key, and Nimbus-minted foreign
 * credentials are well-formed SD-JWT VCs (parseable by walt-id,
 * signature verifiable without walt-id) — so server rejections of
 * these artifacts prove trust gates, not parse failures.
 */
class ThirdPartyFixturesTests {

  private final ObjectMapper mapper = new ObjectMapper();

  @Test
  void checkedInJwksMatchesMintingKey() throws Exception {
    var issuer = NimbusWallet.fixedForeignIssuer(mapper);
    String resource =
        Files.readString(
            Path.of("src/test/resources/openid/third-party-issuer-jwks.json"),
            StandardCharsets.UTF_8);
    var checkedIn = mapper.readTree(resource).get("keys").get(0);
    var minted = mapper.readTree(issuer.jwks(mapper)).get("keys").get(0);
    assertThat(minted.get("x").asString()).isEqualTo(checkedIn.get("x").asString());
    assertThat(minted.get("y").asString()).isEqualTo(checkedIn.get("y").asString());
    assertThat(minted.get("kid").asString()).isEqualTo(checkedIn.get("kid").asString());
    // The pair is consistent: minting signs verifiably under the key.
    var holder = IssuanceFixtures.generateHolder(mapper);
    String credential =
        NimbusWallet.foreignCredential(
            holder, issuer, UUID.randomUUID().toString(), IssuanceFixtures.ADULT_VCT,
            Instant.now(), Instant.now().plusSeconds(3600), mapper);
    ECKey key = (ECKey) ECKey.parse(mapper.writeValueAsString(minted));
    JWSObject head = JWSObject.parse(credential.substring(0, credential.indexOf('~')));
    assertThat(head.verify(new ECDSAVerifier(key))).isTrue();
  }

  @Test
  void foreignCredentialIsWellFormedSdJwt() throws Exception {
    var issuer = NimbusWallet.fixedForeignIssuer(mapper);
    var holder = IssuanceFixtures.generateHolder(mapper);
    String credentialId = UUID.randomUUID().toString();
    String credential =
        NimbusWallet.foreignCredential(
            holder, issuer, credentialId, IssuanceFixtures.ADULT_VCT,
            Instant.now(), Instant.now().plusSeconds(3600), mapper);
    SDJwt parsed = SDJwt.Companion.parse(credential);
    assertThat(parsed.getDisclosures()).hasSize(1);
    var payload = mapper.readTree(parsed.getFullPayload().toString());
    assertThat(payload.get("iss").asString()).isEqualTo(issuer.id());
    assertThat(payload.get("jti").asString()).isEqualTo(credentialId);
    assertThat(payload.get("vct").asString()).isEqualTo(IssuanceFixtures.ADULT_VCT);
    assertThat(payload.get("claims").get("adultOver18").asBoolean()).isTrue();
    assertThat(mapper.readTree(parsed.getHeader().toString()).get("typ").asString())
        .isEqualTo("dc+sd-jwt");
  }
}
