package dev.sovra.crypto;

import com.nimbusds.jose.util.Base64URL;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.spec.ECParameterSpec;

/**
 * Single home for P-256 curve parameters, fixed-width JWK encoding,
 * and RFC 7638 thumbprints. Every P-256 touchpoint — holder-key
 * parsing, synthetic signers, protocol keys, thumbprint-bound ids —
 * funnels through here so the curve, the coordinate encoding, and
 * the thumbprint canonicalization each change in exactly one place.
 * Nothing outside this package re-implements them.
 */
public final class P256 {

  private P256() {}

  /** P-256 parameters from the JDK's own named-curve table. */
  public static ECParameterSpec params() throws Exception {
    java.security.AlgorithmParameters parameters =
        java.security.AlgorithmParameters.getInstance("EC");
    parameters.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
    return parameters.getParameterSpec(ECParameterSpec.class);
  }

  /** Unsigned fixed-32-byte encoding of a P-256 coordinate. */
  public static byte[] fixed32(BigInteger value) {
    byte[] raw = value.toByteArray();
    byte[] fixed = new byte[32];
    System.arraycopy(
        raw,
        Math.max(0, raw.length - 32),
        fixed,
        Math.max(0, 32 - raw.length),
        Math.min(32, raw.length));
    return fixed;
  }

  /** Base64url of the fixed-32-byte coordinate encoding. */
  public static String base64UrlUnsigned(BigInteger value) {
    return Base64URL.encode(fixed32(value)).toString();
  }

  /** RFC 7638 SHA-256 thumbprint of a P-256 public JWK. */
  public static String thumbprint(BigInteger x, BigInteger y) {
    try {
      String canonical =
          "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\""
              + base64UrlUnsigned(x)
              + "\",\"y\":\""
              + base64UrlUnsigned(y)
              + "\"}";
      byte[] digest =
          MessageDigest.getInstance("SHA-256")
              .digest(canonical.getBytes(StandardCharsets.UTF_8));
      return Base64URL.encode(digest).toString();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }
}
