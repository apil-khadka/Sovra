package dev.sovra.openid;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import dev.sovra.issuance.IssuanceFixtures;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.text.ParseException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Independent third-party wallet simulator for SOV-036 protocol tests.
 * Built on Nimbus JOSE + JDK only — it never touches walt-id — so
 * every artifact it mints (VCI proofs, KeyBinding JWTs, encrypted
 * {@code direct_post.jwt} responses, foreign-issuer credentials)
 * exercises the server against a genuinely separate implementation.
 * Test keys are random per call; cross-implementation vectors live in
 * {@code src/test/resources/openid/}.
 */
public final class NimbusWallet {

  private NimbusWallet() {}

  /** KeyBinding JWT (RFC 9901 section 8) over the presented SD-JWT. */
  public static String keyBinding(
      IssuanceFixtures.HolderKeys holder,
      String audience,
      String nonce,
      String presented,
      ObjectMapper mapper)
      throws Exception {
    return keyBindingAt(holder, audience, nonce, presented, Instant.now().getEpochSecond(), mapper);
  }

  /** KeyBinding JWT with an explicit {@code iat} (freshness tests). */
  public static String keyBindingAt(
      IssuanceFixtures.HolderKeys holder,
      String audience,
      String nonce,
      String presented,
      long iat,
      ObjectMapper mapper)
      throws Exception {
    byte[] digest =
        MessageDigest.getInstance("SHA-256").digest(presented.getBytes(StandardCharsets.US_ASCII));
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("aud", audience);
    claims.put("nonce", nonce);
    claims.put("sd_hash", Base64URL.encode(digest).toString());
    claims.put("iat", iat);
    return signCompact(
        holder, "{\"alg\":\"ES256\",\"typ\":\"kb+jwt\"}", mapper.writeValueAsString(claims));
  }

  /** OpenID4VCI {@code jwt} key proof bound to the token's {@code c_nonce}. */
  public static String vciProof(
      IssuanceFixtures.HolderKeys holder, String issuerId, String cNonce, ObjectMapper mapper)
      throws Exception {
    Map<String, Object> header = new LinkedHashMap<>();
    header.put("alg", "ES256");
    header.put("typ", "openid4vci-proof+jwt");
    header.put("jwk", mapper.convertValue(holder.jwk(), Map.class));
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("aud", issuerId);
    claims.put("iat", Instant.now().getEpochSecond());
    claims.put("nonce", cNonce);
    return signCompact(
        holder, mapper.writeValueAsString(header), mapper.writeValueAsString(claims));
  }

  /** Encrypts a {@code direct_post.jwt} response to the verifier key. */
  public static String encryptResponse(String verifierJwkJson, String payloadJson) throws Exception {
    return encryptResponseWith(
        verifierJwkJson, payloadJson, JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM);
  }

  /** Encrypts with an explicit transport (downgrade-attempt fixtures). */
  public static String encryptResponseWith(
      String verifierJwkJson, String payloadJson, JWEAlgorithm alg, EncryptionMethod enc)
      throws Exception {
    ECKey verifier;
    try {
      verifier = ECKey.parse(verifierJwkJson);
    } catch (ParseException e) {
      throw new IllegalArgumentException("verifier key is malformed", e);
    }
    requireP256(verifier);
    JWEObject jwe =
        new JWEObject(
            new JWEHeader.Builder(alg, enc).keyID(verifier.getKeyID()).build(),
            new Payload(payloadJson));
    jwe.encrypt(new ECDHEncrypter(verifier));
    return jwe.serialize();
  }

  /** PKCE S256 challenge for a verifier. */
  public static String pkceChallenge(String verifier) throws Exception {
    byte[] digest =
        MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
    return Base64URL.encode(digest).toString();
  }

  /** Foreign-issuer SD-JWT VC minted without walt-id (untrusted-issuer fixtures). */
  public static String foreignCredential(
      IssuanceFixtures.HolderKeys holder,
      ForeignIssuer issuer,
      String credentialId,
      String vct,
      Instant issuedAt,
      Instant expiresAt,
      ObjectMapper mapper)
      throws Exception {
    byte[] salt = new byte[16];
    new java.security.SecureRandom().nextBytes(salt);
    String disclosureJson =
        "[\"" + Base64URL.encode(salt) + "\",\"adultOver18\",true]";
    String disclosure =
        Base64URL.encode(disclosureJson.getBytes(StandardCharsets.UTF_8)).toString();
    byte[] digest =
        MessageDigest.getInstance("SHA-256").digest(disclosure.getBytes(StandardCharsets.US_ASCII));
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("_sd", new String[] {Base64URL.encode(digest).toString()});
    Map<String, Object> cnf = new LinkedHashMap<>();
    cnf.put("jwk", mapper.convertValue(holder.jwk(), Map.class));
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("iss", issuer.id());
    payload.put("sub", IssuanceFixtures.thumbprint(holder));
    payload.put("jti", credentialId);
    payload.put("iat", issuedAt.getEpochSecond());
    payload.put("exp", expiresAt.getEpochSecond());
    payload.put("vct", vct);
    payload.put("cnf", cnf);
    payload.put("_sd_alg", "sha-256");
    payload.put("claims", claims);
    Map<String, Object> header = new LinkedHashMap<>();
    header.put("alg", "ES256");
    header.put("typ", "dc+sd-jwt");
    header.put("kid", issuer.keyId());
    String jwt =
        signCompact(
            issuer.keys(), mapper.writeValueAsString(header), mapper.writeValueAsString(payload));
    return jwt + "~" + disclosure + "~";
  }

  public record ForeignIssuer(String id, String keyId, IssuanceFixtures.HolderKeys keys) {
    public String jwks(ObjectMapper mapper) throws Exception {
      Map<String, Object> jwk = new LinkedHashMap<>(mapper.convertValue(keys.jwk(), Map.class));
      jwk.put("kid", keyId);
      return mapper.writeValueAsString(Map.of("keys", new Object[] {jwk}));
    }
  }

  /**
   * Fixed third-party issuer (P-256 scalar 3, reproducible vectors).
   * Coordinates must match {@code openid/third-party-issuer-jwks.json};
   * {@link ThirdPartyFixturesTests} pins them together.
   */
  public static ForeignIssuer fixedForeignIssuer(ObjectMapper mapper) throws Exception {
    String x = "Xsvk0aYzCkTI9--VHUvxZebGtyHvramF-0FmG8bn_Ww";
    String y = "hzRkDEmY_343SwbOGmSi7NgqsDY4T7g9mnmxJ6J9UDI";
    java.security.AlgorithmParameters parameters =
        java.security.AlgorithmParameters.getInstance("EC");
    parameters.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
    java.security.spec.ECParameterSpec spec =
        parameters.getParameterSpec(java.security.spec.ECParameterSpec.class);
    java.security.KeyFactory factory = java.security.KeyFactory.getInstance("EC");
    java.security.interfaces.ECPrivateKey privateKey =
        (java.security.interfaces.ECPrivateKey)
            factory.generatePrivate(
                new java.security.spec.ECPrivateKeySpec(java.math.BigInteger.valueOf(3), spec));
    java.security.interfaces.ECPublicKey publicKey =
        (java.security.interfaces.ECPublicKey)
            factory.generatePublic(
                new java.security.spec.ECPublicKeySpec(
                    new java.security.spec.ECPoint(
                        new java.math.BigInteger(
                            1, com.nimbusds.jose.util.Base64URL.from(x).decode()),
                        new java.math.BigInteger(
                            1, com.nimbusds.jose.util.Base64URL.from(y).decode())),
                    spec));
    Map<String, String> jwk = new LinkedHashMap<>();
    jwk.put("kty", "EC");
    jwk.put("crv", "P-256");
    jwk.put("x", x);
    jwk.put("y", y);
    return new ForeignIssuer(
        "https://issuer.example/third-party-1",
        "third-party-issuer-1",
        new IssuanceFixtures.HolderKeys(
            publicKey, privateKey, mapper.readTree(mapper.writeValueAsString(jwk))));
  }

  /** ES256 compact JWS over raw header/payload JSON (shared mint path). */
  static String signCompact(IssuanceFixtures.HolderKeys keys, String headerJson, String payloadJson)
      throws Exception {
    String header = Base64URL.encode(headerJson.getBytes(StandardCharsets.UTF_8)).toString();
    String payload = Base64URL.encode(payloadJson.getBytes(StandardCharsets.UTF_8)).toString();
    Signature signature = Signature.getInstance("SHA256withECDSA");
    signature.initSign(keys.privateKey());
    signature.update((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
    String proof =
        Base64URL.encode(ECDSA.transcodeSignatureToConcat(signature.sign(), 64)).toString();
    return header + "." + payload + "." + proof;
  }

  /** Curve sanity: the wallet only speaks P-256. */
  private static void requireP256(ECKey key) {
    if (!Curve.P_256.equals(key.getCurve())) {
      throw new IllegalArgumentException("verifier key must be P-256");
    }
  }
}
