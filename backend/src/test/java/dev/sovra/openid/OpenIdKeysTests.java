package dev.sovra.openid;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.ECKey;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

class OpenIdKeysTests {

  private final ObjectMapper mapper = new ObjectMapper();

  @Test
  void walletJweRoundTrips() throws Exception {
    OpenIdKeys keys = new OpenIdKeys(true, true);
    String jwks = mapper.writeValueAsString(keys.jwks());
    String keyJson = mapper.writeValueAsString(mapper.readTree(jwks).get("keys").get(0));
    ECKey parsed = (ECKey) ECKey.parse(keyJson);
    assertThat(parsed.getKeyID()).isEqualTo(OpenIdKeys.KEY_ID);
    String payload = "{\"vp_token\":\"abc\",\"state\":\"s\"}";
    String jwe = NimbusWallet.encryptResponse(keyJson, payload);
    assertThat(keys.decryptResponse(jwe)).isEqualTo(payload);
  }

  @Test
  void jwksCarriesSingleP256Key() throws Exception {
    OpenIdKeys keys = new OpenIdKeys(true, true);
    var jwks = mapper.readTree(mapper.writeValueAsString(keys.jwks()));
    assertThat(jwks.get("keys").size()).isEqualTo(1);
    assertThat(jwks.get("keys").get(0).get("crv").asString()).isEqualTo("P-256");
    assertThat(jwks.get("keys").get(0).get("kid").asString()).isEqualTo(OpenIdKeys.KEY_ID);
  }

  @Test
  void requestObjectSignsEs256() throws Exception {
    OpenIdKeys keys = new OpenIdKeys(true, true);
    String jwt = keys.signRequestObject(Map.of("client_id", "aud", "nonce", "n"));
    assertThat(jwt.split("\\.", -1)).hasSize(3);
  }
}
