package dev.sovra.crypto;

import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Shared holder proof-of-possession checks: P-256 public keys only, ES256
 * JWS proofs over a caller-supplied canonical message. Callers bind the
 * message to their exact request; this helper only proves the key holder
 * signed these bytes. Failures throw {@link HolderProofException}, which
 * callers map to their domain error.
 */
public final class HolderProofs {

  private HolderProofs() {}

  public static ECPublicKey parseP256Key(JsonNode jwk) {
    try {
      if (!"EC".equals(text(jwk, "kty")) || !"P-256".equals(text(jwk, "crv"))) {
        throw new HolderProofException("holder key must be P-256");
      }
      BigInteger x = unsigned(text(jwk, "x"));
      BigInteger y = unsigned(text(jwk, "y"));
      ECParameterSpec params = p256Params();
      KeyFactory factory = KeyFactory.getInstance("EC");
      return (ECPublicKey) factory.generatePublic(new ECPublicKeySpec(new ECPoint(x, y), params));
    } catch (HolderProofException e) {
      throw e;
    } catch (Exception e) {
      throw new HolderProofException("holder key is malformed", e);
    }
  }

  /**
   * Verifies an ES256 compact JWS signature over its own signing input,
   * without comparing the payload. Callers check the decoded payload
   * field by field after this returns the split parts.
   */
  public static String[] verifySignature(ECPublicKey key, String jws) {
    try {
      String[] parts = jws.split("\\.", -1);
      if (parts.length != 3) {
        throw new HolderProofException("signature container is malformed");
      }
      Signature signature = Signature.getInstance("SHA256withECDSA");
      signature.initVerify(key);
      signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
      byte[] der = ECDSA.transcodeSignatureToDER(Base64URL.from(parts[2]).decode());
      if (!signature.verify(der)) {
        throw new HolderProofException("signature is invalid");
      }
      return parts;
    } catch (HolderProofException e) {
      throw e;
    } catch (Exception e) {
      throw new HolderProofException("signature is invalid", e);
    }
  }

  /** Verifies an ES256 JWS whose payload is exactly {@code expectedMessage}. */
  public static void verifyEs256(
      ECPublicKey holderKey, String proof, String expectedMessage, ObjectMapper mapper) {
    try {
      String[] parts = proof.split("\\.", -1);
      if (parts.length != 3) {
        throw new HolderProofException("holder proof is malformed");
      }
      JsonNode header = mapper.readTree(Base64URL.from(parts[0]).decode());
      if (!"ES256".equals(text(header, "alg"))) {
        throw new HolderProofException("holder proof must be ES256");
      }
      String message = new String(Base64URL.from(parts[1]).decode(), StandardCharsets.UTF_8);
      if (!MessageDigest.isEqual(
          message.getBytes(StandardCharsets.UTF_8),
          expectedMessage.getBytes(StandardCharsets.UTF_8))) {
        throw new HolderProofException("holder proof does not match this request");
      }
      Signature signature = Signature.getInstance("SHA256withECDSA");
      signature.initVerify(holderKey);
      signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
      byte[] der = ECDSA.transcodeSignatureToDER(Base64URL.from(parts[2]).decode());
      if (!signature.verify(der)) {
        throw new HolderProofException("holder proof signature is invalid");
      }
    } catch (HolderProofException e) {
      throw e;
    } catch (JacksonException e) {
      throw new HolderProofException("holder proof is malformed", e);
    } catch (Exception e) {
      throw new HolderProofException("holder proof is invalid", e);
    }
  }

  /** P-256 parameters from the JDK's own named-curve table. */
  private static ECParameterSpec p256Params() throws Exception {
    java.security.AlgorithmParameters parameters =
        java.security.AlgorithmParameters.getInstance("EC");
    parameters.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
    return parameters.getParameterSpec(ECParameterSpec.class);
  }

  private static String text(JsonNode node, String field) {
    JsonNode child = node == null ? null : node.get(field);
    return child != null && child.isString() ? child.asString() : null;
  }

  private static BigInteger unsigned(String base64Url) {
    if (base64Url == null) {
      throw new HolderProofException("holder key is malformed");
    }
    byte[] raw;
    try {
      raw = Base64URL.from(base64Url).decode();
    } catch (Exception e) {
      throw new HolderProofException("holder key is malformed", e);
    }
    if (raw.length != 32) {
      throw new HolderProofException("holder key is malformed");
    }
    return new BigInteger(1, raw);
  }
}
