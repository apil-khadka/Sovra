package dev.sovra.openid;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * G1 synthetic OpenID verifier keys (SOV-036). One deterministic P-256
 * keypair serves both OpenID4VP roles that need server-side crypto:
 * signing authorization request objects (ES256) and decrypting
 * {@code direct_post.jwt} responses (ECDH-ES+A256KW / A256GCM).
 *
 * <p>The private scalar is 2 — as obviously non-secret as the
 * issuance scalar 1 — held in memory only and armed by the same two
 * synthetic flags. Both app instances derive the identical key, so a
 * wallet response lands on either instance behind the entry point.
 * Production retires this class for KMS-backed verifier keys.
 */
@Service
public class OpenIdKeys {

  public static final String KEY_ID = "sovra-vp-synth-1";
  public static final String VERIFIER_ID = "https://sovra.example/verifiers/synth-1";

  private final ECPrivateKey privateKey;
  private final ECPublicKey publicKey;
  private final ECKey publicJwk;

  public OpenIdKeys(
      @Value("${sovra.synthetic-issuers.enabled:false}") boolean enabled,
      @Value("${sovra.synthetic-issuers.acknowledge-non-production:false}")
          boolean acknowledged)
      throws Exception {
    if (!enabled || !acknowledged) {
      throw new IllegalStateException(
          "OpenIdKeys needs both sovra.synthetic-issuers.enabled and"
              + " sovra.synthetic-issuers.acknowledge-non-production set to true");
    }
    ECParameterSpec params = ECP256.params();
    KeyFactory factory = KeyFactory.getInstance("EC");
    this.privateKey =
        (ECPrivateKey) factory.generatePrivate(new ECPrivateKeySpec(BigInteger.TWO, params));
    ECPoint generator = params.getGenerator();
    // Scalar 2: public point is 2G over the named-curve parameters.
    ECPoint doubled = doublePoint(generator, params);
    this.publicKey =
        (ECPublicKey) factory.generatePublic(new ECPublicKeySpec(doubled, params));
    this.publicJwk =
        new ECKey.Builder(Curve.P_256, publicJwkX(), publicJwkY())
            .keyID(KEY_ID)
            .keyUse(null)
            .build();
  }

  /** Signs an authorization request object (ES256, {@code kid} set). */
  public String signRequestObject(Map<String, Object> claims) {
    try {
      SignedJWT jwt =
          new SignedJWT(
              new JWSHeader.Builder(JWSAlgorithm.ES256)
                  .type(JOSEObjectType.JWT)
                  .keyID(KEY_ID)
                  .build(),
              com.nimbusds.jwt.JWTClaimsSet.parse(claims));
      jwt.sign(new ECDSASigner(privateKey));
      return jwt.serialize();
    } catch (Exception e) {
      throw new IllegalStateException("request-object signing failed", e);
    }
  }

  /**
   * Decrypts a {@code direct_post.jwt} JWE addressed to the verifier
   * key. The header must name exactly the frozen transport
   * ({@code ECDH-ES+A256KW} / {@code A256GCM}); anything else is a
   * downgrade attempt and is rejected before decryption.
   */
  public String decryptResponse(String jwe) {
    try {
      EncryptedJWT parsed = EncryptedJWT.parse(jwe);
      if (!"ECDH-ES+A256KW".equals(parsed.getHeader().getAlgorithm().getName())
          || !com.nimbusds.jose.EncryptionMethod.A256GCM.equals(
              parsed.getHeader().getEncryptionMethod())) {
        throw new InvalidOpenIdRequestException("response transport is out of profile");
      }
      ECKey decryptionKey =
          new ECKey.Builder(Curve.P_256, publicJwkX(), publicJwkY())
              .privateKey(privateKey)
              .keyID(KEY_ID)
              .build();
      parsed.decrypt(new ECDHDecrypter(decryptionKey));
      Payload payload = parsed.getPayload();
      if (payload == null) {
        throw new InvalidOpenIdRequestException("response payload is empty");
      }
      return payload.toString();
    } catch (ParseException e) {
      throw new InvalidOpenIdRequestException("response is not a JWE");
    } catch (InvalidOpenIdRequestException e) {
      throw e;
    } catch (Exception e) {
      throw new InvalidOpenIdRequestException("response decryption failed");
    }
  }

  /** Public verifier JWKS (signing + encryption use the one G1 key). */
  public Map<String, Object> jwks() {
    return Map.of(
        "keys",
        List.of(
            Map.of(
                "kty", "EC",
                "crv", "P-256",
                "kid", KEY_ID,
                "x", publicJwk.getX().toString(),
                "y", publicJwk.getY().toString())));
  }

  ECPublicKey publicKey() {
    return publicKey;
  }

  private com.nimbusds.jose.util.Base64URL publicJwkX() {
    return com.nimbusds.jose.util.Base64URL.encode(unsigned(publicKey.getW().getAffineX()));
  }

  private com.nimbusds.jose.util.Base64URL publicJwkY() {
    return com.nimbusds.jose.util.Base64URL.encode(unsigned(publicKey.getW().getAffineY()));
  }

  private static byte[] unsigned(BigInteger value) {
    byte[] raw = value.toByteArray();
    byte[] fixed = new byte[32];
    System.arraycopy(
        raw, Math.max(0, raw.length - 32), fixed, Math.max(0, 32 - raw.length),
        Math.min(32, raw.length));
    return fixed;
  }

  /**
   * Point doubling on P-256 through JCA ECDH-free arithmetic. The inputs
   * are the curve parameters, never secret material beyond scalar 2.
   */
  private static ECPoint doublePoint(ECPoint p, ECParameterSpec params) {
    BigInteger prime =
        ((java.security.spec.ECFieldFp) params.getCurve().getField()).getP();
    BigInteger a = params.getCurve().getA();
    BigInteger x = p.getAffineX();
    BigInteger y = p.getAffineY();
    BigInteger slope =
        x.multiply(x)
            .multiply(BigInteger.valueOf(3))
            .add(a)
            .multiply(y.multiply(BigInteger.TWO).modInverse(prime))
            .mod(prime);
    BigInteger rx = slope.multiply(slope).subtract(x.multiply(BigInteger.TWO)).mod(prime);
    BigInteger ry = slope.multiply(x.subtract(rx)).subtract(y).mod(prime);
    return new ECPoint(rx, ry);
  }

  /** P-256 parameters from the JDK's own named-curve table. */
  static final class ECP256 {
    private ECP256() {}

    static ECParameterSpec params() throws Exception {
      java.security.AlgorithmParameters parameters =
          java.security.AlgorithmParameters.getInstance("EC");
      parameters.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
      return parameters.getParameterSpec(ECParameterSpec.class);
    }
  }
}
