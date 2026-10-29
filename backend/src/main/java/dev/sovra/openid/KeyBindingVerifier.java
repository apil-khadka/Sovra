package dev.sovra.openid;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import dev.sovra.crypto.HolderProofException;
import id.walt.sdjwt.JWTCryptoProvider;
import id.walt.sdjwt.JwtVerificationResult;
import id.walt.sdjwt.KeyBindingJwt;
import id.walt.sdjwt.SDJwt;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.time.Duration;

/**
 * KeyBinding JWT verification per RFC 9901 section 8 (SOV-036).
 * Parsing, claim access, {@code sd_hash}, and the signature check run
 * through the qualified walt-id {@link KeyBindingJwt} interface
 * against the holder key the credential's {@code cnf} names — never
 * a key from the presentation itself. Sovra owns the conjunction
 * explicitly (walt-id's {@code verifyKB} only accepts its own
 * presentation objects, while G1 binds the issued bytes verbatim),
 * pins the JOSE header ({@code alg} ES256, {@code typ} {@code kb+jwt})
 * and the freshness window (SOV-001 section 4 skew, symmetric), and
 * recomputes {@code sd_hash} with the JDK independently of walt-id.
 *
 * <p>Failures throw {@link HolderProofException}; callers map it to
 * their domain error ({@code BINDING_INVALID} on the verification
 * path). Walt-id parse errors embed the artifact, so their messages
 * are never propagated.
 */
public final class KeyBindingVerifier {

  /** Symmetric freshness window for the KB {@code iat} (SOV-001 5m). */
  static final Duration IAT_WINDOW = Duration.ofMinutes(5);

  private KeyBindingVerifier() {}

  /**
   * Verifies a KeyBinding JWT against the presented SD-JWT string.
   *
   * @param kbJwt compact KeyBinding JWT from the holder
   * @param holderKey holder P-256 key from the credential {@code cnf}
   * @param audience expected verifier audience
   * @param nonce expected single-use verifier nonce
   * @param presented the exact SD-JWT presentation string the KB binds
   * @param clock clock for the {@code iat} window
   */
  public static void verify(
      String kbJwt,
      ECPublicKey holderKey,
      String audience,
      String nonce,
      String presented,
      Clock clock) {
    if (kbJwt == null || kbJwt.isBlank() || presented == null || presented.isBlank()) {
      throw new HolderProofException("key binding is missing");
    }
    KeyBindingJwt parsed;
    try {
      parsed = KeyBindingJwt.Companion.parse(kbJwt);
    } catch (RuntimeException e) {
      throw new HolderProofException("key binding is malformed");
    }
    String alg = headerText(parsed, "alg");
    String typ = headerText(parsed, "typ");
    if (!"ES256".equals(alg) || !"kb+jwt".equals(typ)) {
      throw new HolderProofException("key binding must be ES256 kb+jwt");
    }
    if (!constantEquals(parsed.getAudience(), audience)
        || !constantEquals(parsed.getNonce(), nonce)) {
      throw new HolderProofException("key binding is not for this request");
    }
    // sd_hash over the exact presented bytes: walt-id's hash and the
    // JDK recomputation must both match the claim.
    String waltHash;
    try {
      waltHash = KeyBindingJwt.Companion.getSdHash(presented);
    } catch (RuntimeException e) {
      throw new HolderProofException("presentation is malformed");
    }
    String jdkHash;
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256")
              .digest(presented.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
      jdkHash = com.nimbusds.jose.util.Base64URL.encode(digest).toString();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
    if (!constantEquals(waltHash, parsed.getSdHash())
        || !constantEquals(jdkHash, parsed.getSdHash())) {
      throw new HolderProofException("key binding does not match this presentation");
    }
    try {
      SDJwt.Companion.parse(presented);
    } catch (RuntimeException e) {
      throw new HolderProofException("presentation is malformed");
    }
    boolean verified;
    try {
      verified = parsed.verify(new VerifyOnlyProvider(holderKey), "").getVerified();
    } catch (RuntimeException e) {
      throw new HolderProofException("key binding is invalid");
    }
    if (!verified) {
      throw new HolderProofException("key binding is invalid");
    }
    long now = clock.instant().getEpochSecond();
    long iat = parsed.getIssuedAt();
    long window = IAT_WINDOW.getSeconds();
    if (iat > now + window || iat < now - window) {
      throw new HolderProofException("key binding is stale");
    }
  }

  private static boolean constantEquals(String actual, String expected) {
    if (actual == null || expected == null) {
      return false;
    }
    return MessageDigest.isEqual(
        actual.getBytes(java.nio.charset.StandardCharsets.UTF_8),
        expected.getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }

  private static String headerText(KeyBindingJwt parsed, String field) {
    try {
      kotlinx.serialization.json.JsonElement child = parsed.getHeader().get(field);
      if (child instanceof kotlinx.serialization.json.JsonPrimitive primitive
          && primitive.isString()) {
        return primitive.getContent();
      }
    } catch (RuntimeException e) {
      // Fall through to null.
    }
    return null;
  }

  /** Verification-only crypto provider: signs nothing, verifies with one key. */
  private static final class VerifyOnlyProvider implements JWTCryptoProvider {
    private final ECPublicKey key;

    VerifyOnlyProvider(ECPublicKey key) {
      this.key = key;
    }

    @Override
    public String sign(
        kotlinx.serialization.json.JsonObject payload,
        String keyID,
        String typ,
        java.util.Map<String, ?> headers) {
      throw new UnsupportedOperationException("verification-only provider");
    }

    @Override
    public JwtVerificationResult verify(String jwt, String keyID) {
      try {
        boolean ok =
            com.nimbusds.jwt.SignedJWT.parse(jwt).verify(new ECDSAVerifier(key));
        return new JwtVerificationResult(ok, "");
      } catch (Exception e) {
        return new JwtVerificationResult(false, "");
      }
    }
  }
}
