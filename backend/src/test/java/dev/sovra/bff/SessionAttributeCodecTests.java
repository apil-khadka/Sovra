package dev.sovra.bff;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.bff.HolderUnlockService.Unlock;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * Session attribute bytes (PROD-003): every supported type
 * round-trips through JSON envelopes — never Java serialization —
 * and every unknown or corrupt input degrades to a dropped
 * attribute, which readers treat as anonymous or locked.
 */
class SessionAttributeCodecTests {

  SessionAttributeCodec codec = new SessionAttributeCodec();

  @Test
  void stringsRoundTrip() {
    byte[] bytes = codec.encode("550e8400-e29b-41d4-a716-446655440000");
    assertThat(envelope(bytes)).startsWith("{\"t\":\"s\"");
    assertThat(codec.decode(bytes)).isEqualTo("550e8400-e29b-41d4-a716-446655440000");
  }

  @Test
  void stringListsRoundTrip() {
    byte[] bytes = codec.encode(List.of("pwd", "webauthn"));
    assertThat(codec.decode(bytes)).isEqualTo(List.of("pwd", "webauthn"));
  }

  @Test
  void unlockGrantsRoundTrip() {
    Unlock bound = new Unlock("thumbprint-abc", Instant.parse("2026-11-02T00:15:00Z"));
    byte[] bytes = codec.encode(bound);
    assertThat(envelope(bytes)).startsWith("{\"t\":\"unlock\"");
    assertThat(codec.decode(bytes)).isEqualTo(bound);
  }

  @Test
  void oauth2AuthorizationRequestsRoundTrip() {
    OAuth2AuthorizationRequest request =
        OAuth2AuthorizationRequest.authorizationCode()
            .clientId("sovra-bff")
            .authorizationUri("http://localhost:18080/realms/sovra/protocol/openid-connect/auth")
            .redirectUri("http://localhost:18088/login/oauth2/code/sovra")
            .scopes(Set.of("openid", "profile"))
            .state("state-value")
            .attributes(Map.of("code_verifier", "verifier-value"))
            .additionalParameters(Map.of("code_challenge", "challenge-value"))
            .build();
    byte[] bytes = codec.encode(request);
    assertThat(envelope(bytes)).startsWith("{\"t\":\"oauth2ar\"");
    Object decoded = codec.decode(bytes);
    assertThat(decoded).isInstanceOf(OAuth2AuthorizationRequest.class);
    OAuth2AuthorizationRequest back = (OAuth2AuthorizationRequest) decoded;
    assertThat(back.getClientId()).isEqualTo("sovra-bff");
    assertThat(back.getState()).isEqualTo("state-value");
    assertThat(back.getAttributes()).containsEntry("code_verifier", "verifier-value");
    assertThat(back.getAdditionalParameters()).containsEntry("code_challenge", "challenge-value");
  }

  @Test
  void frameworkContextObjectsAreNeverStored() {
    // The session holds a marker string instead (see
    // BffSecurityContextRepository); the OIDC object graph must
    // fail fast here rather than silently land in a row.
    assertThatThrownBy(() -> codec.encode(new SecurityContextImpl()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("unsupported session attribute type");
  }

  @Test
  void attributeBytesAreJsonNeverJavaSerialization() {
    // Java serialization starts with 0xAC 0xED; these bytes must
    // always start with the JSON envelope instead.
    assertThat(codec.encode("x")[0]).isEqualTo((byte) '{');
    assertThat(codec.encode(List.of("x"))[0]).isEqualTo((byte) '{');
    assertThat(codec.encode(new Unlock("t", Instant.EPOCH))[0]).isEqualTo((byte) '{');
  }

  @Test
  void unknownJavaTypesFailFastOnWrite() {
    assertThatThrownBy(() -> codec.encode(42))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("unsupported session attribute type");
    assertThatThrownBy(() -> codec.encode(null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void unknownAndCorruptAttributesDropToNull() {
    assertThat(codec.decode(json("{\"t\":\"nope\",\"v\":1}"))).isNull();
    assertThat(codec.decode(json("not json at all"))).isNull();
    assertThat(codec.decode(json("[1,2,3]"))).isNull();
    assertThat(codec.decode(json("{\"v\":\"missing-type\"}"))).isNull();
    assertThat(codec.decode(new byte[] {(byte) 0xAC, (byte) 0xED, 0x00, 0x05})).isNull();
  }

  @Test
  void mistypedValuesDropToNull() {
    assertThat(codec.decode(json("{\"t\":\"s\",\"v\":42}"))).isNull();
    assertThat(codec.decode(json("{\"t\":\"sl\",\"v\":\"nope\"}"))).isNull();
    assertThat(codec.decode(json("{\"t\":\"sl\",\"v\":[\"ok\",42]}"))).isNull();
    assertThat(codec.decode(json("{\"t\":\"unlock\",\"v\":{\"thumbprint\":42}}"))).isNull();
  }

  private static byte[] json(String raw) {
    return raw.getBytes(StandardCharsets.UTF_8);
  }

  private static String envelope(byte[] bytes) {
    return new String(bytes, StandardCharsets.UTF_8);
  }
}
