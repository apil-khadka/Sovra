package dev.sovra.sdk;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Map;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Test-only P-256 holder keys and ES256 proof signing, mirroring
 * the server's proof formats. Never ships in the SDK jar's API.
 */
final class TestHolders {

  record HolderKeys(ECPublicKey publicKey, ECPrivateKey privateKey, JsonNode jwk) {}

  private TestHolders() {}

  static HolderKeys generate(ObjectMapper mapper) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair pair = generator.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) pair.getPublic();
    Map<String, String> jwk = Map.of(
        "kty", "EC", "crv", "P-256",
        "x", base64UrlUnsigned(pub.getW().getAffineX()),
        "y", base64UrlUnsigned(pub.getW().getAffineY()));
    return new HolderKeys(
        pub, (ECPrivateKey) pair.getPrivate(),
        mapper.readTree(mapper.writeValueAsString(jwk)));
  }

  static String thumbprint(HolderKeys holder) {
    String canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\""
        + base64UrlUnsigned(holder.publicKey().getW().getAffineX()) + "\",\"y\":\""
        + base64UrlUnsigned(holder.publicKey().getW().getAffineY()) + "\"}";
    try {
      byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
          .digest(canonical.getBytes(StandardCharsets.UTF_8));
      return base64Url(digest);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  static String base64UrlUnsigned(BigInteger value) {
    byte[] raw = value.toByteArray();
    byte[] fixed = new byte[32];
    System.arraycopy(raw, Math.max(0, raw.length - 32), fixed, Math.max(0, 32 - raw.length),
        Math.min(32, raw.length));
    return base64Url(fixed);
  }

  static String base64Url(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  /** ES256 JWS (raw R||S) over an arbitrary message. */
  static String proofOver(HolderKeys holder, String message) throws Exception {
    String header = base64Url("{\"alg\":\"ES256\"}".getBytes(StandardCharsets.UTF_8));
    String payload = base64Url(message.getBytes(StandardCharsets.UTF_8));
    Signature signature = Signature.getInstance("SHA256withECDSA");
    signature.initSign(holder.privateKey());
    signature.update((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
    return header + "." + payload + "." + base64Url(transcodeToConcat(signature.sign()));
  }

  /** DER ECDSA signature to 64-byte R||S. */
  static byte[] transcodeToConcat(byte[] der) {
    int offset = 2;
    int rLength = der[offset + 1];
    offset += 2;
    byte[] r = new byte[32];
    System.arraycopy(der, offset + Math.max(0, rLength - 32), r, Math.max(0, 32 - rLength),
        Math.min(32, rLength));
    offset += rLength + 2;
    int sLength = der[offset - 1];
    byte[] s = new byte[32];
    System.arraycopy(der, offset + Math.max(0, sLength - 32), s, Math.max(0, 32 - sLength),
        Math.min(32, sLength));
    byte[] concat = new byte[64];
    System.arraycopy(r, 0, concat, 0, 32);
    System.arraycopy(s, 0, concat, 32, 32);
    return concat;
  }
}
