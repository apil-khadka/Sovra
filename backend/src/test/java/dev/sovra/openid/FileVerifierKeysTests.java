package dev.sovra.openid;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Production verifier keys (PROD-005): random file-mounted P-256
 * keypairs with versioned kids, signing/decryption separation, and
 * overlap decryption across rotation. Missing or malformed files
 * fail construction (fail boot), never degrade to the fixture.
 */
class FileVerifierKeysTests {

  @TempDir Path keys;

  @Test
  @SuppressWarnings("unchecked")
  void signAndVerifyRoundtrip() throws Exception {
    Path signing = writeKey("sign");
    Path decrypt = writeKey("dec");
    FileVerifierKeys verifier =
        new FileVerifierKeys(
            signing.toString(), "sovra-vp-sign-v3", decrypt.toString(), "sovra-vp-dec-v5");
    String requestObject =
        verifier.signRequestObject(Map.of("client_id", "sovra-bff", "nonce", "n-1"));
    SignedJWT parsed = SignedJWT.parse(requestObject);
    assertThat(parsed.getHeader().getKeyID()).isEqualTo("sovra-vp-sign-v3");
    ECKey publicJwk = publicJwk(signing, "sovra-vp-sign-v3");
    assertThat(parsed.verify(new ECDSAVerifier(publicJwk))).isTrue();
    assertThat(parsed.getJWTClaimsSet().getStringClaim("nonce")).isEqualTo("n-1");
  }

  @Test
  void encryptDecryptRoundtrip() throws Exception {
    Path signing = writeKey("sign");
    Path decrypt = writeKey("dec");
    FileVerifierKeys verifier =
        new FileVerifierKeys(
            signing.toString(), "sovra-vp-sign-v1", decrypt.toString(), "sovra-vp-dec-v1");
    String jwe = encrypt(publicJwk(decrypt, "sovra-vp-dec-v1"), "wallet-response-payload");
    assertThat(verifier.decryptResponse(jwe)).isEqualTo("wallet-response-payload");
  }

  @Test
  void rotationOverlapDecryptsWithPrevious() throws Exception {
    Path signing = writeKey("sign");
    Path current = writeKey("current");
    Path previous = writeKey("previous");
    FileVerifierKeys verifier =
        new FileVerifierKeys(
            signing.toString(),
            "sovra-vp-sign-v2",
            current + "," + previous,
            "sovra-vp-dec-v2,sovra-vp-dec-v1");
    // In-flight response sealed to the previous key still opens.
    String jwe = encrypt(publicJwk(previous, "sovra-vp-dec-v1"), "in-flight-payload");
    assertThat(verifier.decryptResponse(jwe)).isEqualTo("in-flight-payload");
    // And the current key works too.
    String fresh = encrypt(publicJwk(current, "sovra-vp-dec-v2"), "fresh-payload");
    assertThat(verifier.decryptResponse(fresh)).isEqualTo("fresh-payload");
  }

  @Test
  void foreignKeyResponsesRefuse() throws Exception {
    Path signing = writeKey("sign");
    Path decrypt = writeKey("dec");
    FileVerifierKeys verifier =
        new FileVerifierKeys(
            signing.toString(), "sovra-vp-sign-v1", decrypt.toString(), "sovra-vp-dec-v1");
    Path stranger = writeKey("stranger");
    String jwe = encrypt(publicJwk(stranger, "stranger-v1"), "nope");
    assertThatThrownBy(() -> verifier.decryptResponse(jwe))
        .isInstanceOf(InvalidOpenIdRequestException.class);
    assertThatThrownBy(() -> verifier.decryptResponse("not-a-jwe"))
        .isInstanceOf(InvalidOpenIdRequestException.class);
  }

  @Test
  @SuppressWarnings("unchecked")
  void jwksListsVersionedKeysWithoutPrivateMaterial() throws Exception {
    Path signing = writeKey("sign");
    Path decrypt = writeKey("dec");
    FileVerifierKeys verifier =
        new FileVerifierKeys(
            signing.toString(), "sovra-vp-sign-v4", decrypt.toString(), "sovra-vp-dec-v4");
    List<Map<String, Object>> published =
        (List<Map<String, Object>>) verifier.jwks().get("keys");
    assertThat(published).hasSize(2);
    assertThat(published.get(0)).containsEntry("kid", "sovra-vp-sign-v4")
        .containsEntry("use", "sig");
    assertThat(published.get(1)).containsEntry("kid", "sovra-vp-dec-v4")
        .containsEntry("use", "enc");
    for (Map<String, Object> entry : published) {
      assertThat(entry).doesNotContainKey("d");
    }
  }

  @Test
  void missingFilesFailConstruction() throws Exception {
    Path signing = writeKey("sign");
    assertThatThrownBy(
            () -> new FileVerifierKeys(
                signing.toString(), "kid", keys.resolve("absent.pem").toString(), "kid"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("unreadable");
    assertThatThrownBy(
            () -> new FileVerifierKeys("", "kid", signing.toString(), "kid"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("must name a verifier key file");
  }

  @Test
  void mismatchedDecryptionSetsFailConstruction() throws Exception {
    Path signing = writeKey("sign");
    Path decrypt = writeKey("dec");
    assertThatThrownBy(
            () -> new FileVerifierKeys(
                signing.toString(), "s", decrypt.toString(), "a,b"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("same non-empty key set");
    assertThatThrownBy(
            () -> new FileVerifierKeys(signing.toString(), "s", "", ""))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("same non-empty key set");
    assertThatThrownBy(
            () -> new FileVerifierKeys(signing.toString(), " ", decrypt.toString(), "d"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("must be a non-blank kid");
  }

  @Test
  void malformedFilesFailConstruction() throws Exception {
    Path signing = writeKey("sign");
    Path garbage = keys.resolve("garbage.pem");
    Files.writeString(garbage, "not a key\n");
    assertThatThrownBy(
            () -> new FileVerifierKeys(
                signing.toString(), "s", garbage.toString(), "d"))
        .isInstanceOf(IllegalStateException.class);
    Path half = keys.resolve("half.pem");
    Files.writeString(half, privatePem(signingKeyPair()));
    assertThatThrownBy(() -> FileVerifierKeys.load(half, "d"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("PUBLIC KEY");
  }

  private Path writeKey(String name) throws Exception {
    KeyPair pair = signingKeyPair();
    Path file = keys.resolve(name + ".pem");
    Files.writeString(
        file, privatePem(pair) + publicPem((ECPublicKey) pair.getPublic()));
    return file;
  }

  private ECKey publicJwk(Path file, String kid) throws Exception {
    return FileVerifierKeys.load(file, kid).toPublicJWK();
  }

  private String encrypt(ECKey publicKey, String payload) throws Exception {
    JWEObject jwe =
        new JWEObject(
            new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM)
                .keyID(publicKey.getKeyID())
                .build(),
            new Payload(payload));
    jwe.encrypt(new ECDHEncrypter(publicKey));
    return jwe.serialize();
  }

  private static KeyPair signingKeyPair() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    return generator.generateKeyPair();
  }

  private static String privatePem(KeyPair pair) {
    return armor("PRIVATE KEY", pair.getPrivate().getEncoded());
  }

  private static String publicPem(ECPublicKey key) {
    return armor("PUBLIC KEY", key.getEncoded());
  }

  private static String armor(String label, byte[] der) {
    String body =
        Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der);
    return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
  }

}
