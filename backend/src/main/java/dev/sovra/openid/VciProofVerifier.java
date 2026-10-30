package dev.sovra.openid;

import com.nimbusds.jose.util.Base64URL;
import dev.sovra.crypto.HolderProofException;
import dev.sovra.crypto.HolderProofs;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * OpenID4VCI {@code jwt} proof verification (SOV-036). The proof
 * carries {@code typ} {@code openid4vci-proof+jwt}, holder key in the
 * {@code jwk} header matching the request key, {@code aud} naming
 * this credential issuer, and {@code nonce} equal to the token's
 * single-use {@code c_nonce}. Freshness comes from the single-use
 * nonce; the {@code iat} must additionally sit inside the 5-minute
 * skew window. Secret-adjacent comparisons ({@code aud},
 * {@code nonce}) run in constant time.
 *
 * <p>Failures throw {@link HolderProofException}; callers map it to
 * their domain error (issuance preserves the message verbatim).
 */
public final class VciProofVerifier {

  /** Symmetric freshness window for the proof {@code iat} (5m). */
  static final Duration IAT_WINDOW = Duration.ofMinutes(5);

  private VciProofVerifier() {}

  /**
   * Verifies a VCI proof JWT against the expected issuer and nonce.
   *
   * @param proofJwt compact proof JWT from the holder
   * @param holderKey holder P-256 key the request binds
   * @param expectedIssuer issuer id the {@code aud} must name
   * @param cNonce single-use nonce the proof must repeat
   * @param now clock for the {@code iat} window
   * @param mapper JSON reader
   */
  public static void verify(
      String proofJwt,
      ECPublicKey holderKey,
      String expectedIssuer,
      String cNonce,
      Instant now,
      ObjectMapper mapper) {
    try {
      String[] parts = proofJwt.split("\\.", -1);
      if (parts.length != 3) {
        throw new HolderProofException("holder proof is malformed");
      }
      JsonNode header = mapper.readTree(Base64URL.from(parts[0]).decode());
      if (!"ES256".equals(text(header, "alg"))
          || !"openid4vci-proof+jwt".equals(text(header, "typ"))) {
        throw new HolderProofException("holder proof must be an ES256 VCI proof JWT");
      }
      JsonNode proofJwk = header.get("jwk");
      if (proofJwk == null || !proofJwk.isObject()) {
        throw new HolderProofException("holder proof must carry its key");
      }
      ECPublicKey proofKey = HolderProofs.parseP256Key(proofJwk);
      if (!proofKey.getW().getAffineX().equals(holderKey.getW().getAffineX())
          || !proofKey.getW().getAffineY().equals(holderKey.getW().getAffineY())) {
        throw new HolderProofException("holder proof key does not match this request");
      }
      JsonNode body = mapper.readTree(Base64URL.from(parts[1]).decode());
      String aud = text(body, "aud");
      if (aud == null
          || !MessageDigest.isEqual(
              aud.getBytes(StandardCharsets.UTF_8),
              expectedIssuer.getBytes(StandardCharsets.UTF_8))) {
        throw new HolderProofException("holder proof audience is wrong");
      }
      if (!MessageDigest.isEqual(
          String.valueOf(text(body, "nonce")).getBytes(StandardCharsets.UTF_8),
          cNonce.getBytes(StandardCharsets.UTF_8))) {
        throw new HolderProofException("holder proof nonce is wrong");
      }
      JsonNode iat = body.get("iat");
      if (iat == null || !iat.isNumber()
          || Math.abs(now.getEpochSecond() - iat.asLong()) > IAT_WINDOW.getSeconds()) {
        throw new HolderProofException("holder proof is stale");
      }
      // Field checks above are VCI-specific; the signature tail is
      // the shared one. (A corrupt signature container surfaces as a
      // signature failure, which is the accurate wording here.)
      try {
        HolderProofs.verifySignature(holderKey, proofJwt);
      } catch (HolderProofException e) {
        throw new HolderProofException("holder proof signature is invalid");
      }
    } catch (HolderProofException e) {
      throw e;
    } catch (JacksonException e) {
      throw new HolderProofException("holder proof is malformed");
    } catch (Exception e) {
      throw new HolderProofException("holder proof is invalid");
    }
  }

  private static String text(JsonNode node, String field) {
    JsonNode child = node == null ? null : node.get(field);
    return child != null && child.isString() ? child.asString() : null;
  }
}
