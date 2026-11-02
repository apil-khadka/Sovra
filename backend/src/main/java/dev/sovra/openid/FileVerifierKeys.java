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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

/**
 * Production OpenID4VP verifier keys (PROD-005). Private keys load
 * from PEM files mounted read-only (vault-agent shape): one
 * signing key plus an ordered decryption set, each with its own
 * versioned {@code kid}. Rotation is overlap-first — the previous
 * decryption key stays listed until in-flight responses drain —
 * then a rolling restart on the new files.
 *
 * <p>Each key file holds a PKCS#8 private key plus the X.509 public
 * key (both `openssl`-native):
 *
 * <pre>
 * openssl ecparam -genkey -name prime256v1 -noout -out vp-sign.key
 * openssl ec -in vp-sign.key -pubout -out vp-sign.pub
 * cat vp-sign.key vp-sign.pub &gt; vp-sign.pem
 * </pre>
 *
 * <p>Missing or unreadable files fail boot, never degrade to the
 * deterministic fixture.
 */
@Service
@ConditionalOnProperty(name = "sovra.openid.keys", havingValue = "file")
public class FileVerifierKeys implements VerifierKeys {

  private final ECPrivateKey signingKey;
  private final String signingKid;
  private final ECKey signingJwk;
  private final List<DecryptionKey> decryptionKeys;

  record DecryptionKey(ECKey jwk, String kid) {}

  public FileVerifierKeys(
      @Value("${sovra.openid.signing-key-path:}") String signingKeyPath,
      @Value("${sovra.openid.signing-kid:}") String signingKid,
      @Value("${sovra.openid.decryption-key-paths:}") String decryptionKeyPaths,
      @Value("${sovra.openid.decryption-kids:}") String decryptionKids) {
    this.signingKid = requireKid("sovra.openid.signing-kid", signingKid);
    ECKey signing =
        load(requirePath("sovra.openid.signing-key-path", signingKeyPath), this.signingKid);
    try {
      this.signingKey = signing.toECPrivateKey();
    } catch (Exception e) {
      throw new IllegalStateException("signing key has no private half", e);
    }
    this.signingJwk = signing;
    String[] paths = splitList(decryptionKeyPaths);
    String[] kids = splitList(decryptionKids);
    if (paths.length == 0 || paths.length != kids.length) {
      throw new IllegalStateException(
          "sovra.openid.decryption-key-paths and sovra.openid.decryption-kids"
              + " must list the same non-empty key set in order (current first)");
    }
    List<DecryptionKey> loaded = new ArrayList<>();
    for (int i = 0; i < paths.length; i++) {
      String kid = requireKid("sovra.openid.decryption-kids[" + i + "]", kids[i]);
      loaded.add(new DecryptionKey(load(requirePath("decryption key", paths[i]), kid), kid));
    }
    this.decryptionKeys = List.copyOf(loaded);
  }

  @Override
  public String signRequestObject(Map<String, Object> claims) {
    try {
      SignedJWT jwt =
          new SignedJWT(
              new JWSHeader.Builder(JWSAlgorithm.ES256)
                  .type(JOSEObjectType.JWT)
                  .keyID(signingKid)
                  .build(),
              com.nimbusds.jwt.JWTClaimsSet.parse(claims));
      jwt.sign(new ECDSASigner(signingKey));
      return jwt.serialize();
    } catch (Exception e) {
      throw new IllegalStateException("request-object signing failed", e);
    }
  }

  @Override
  public String decryptResponse(String jwe) {
    EncryptedJWT parsed;
    try {
      parsed = EncryptedJWT.parse(jwe);
    } catch (ParseException e) {
      throw new InvalidOpenIdRequestException("response is not a JWE");
    }
    if (!"ECDH-ES+A256KW".equals(parsed.getHeader().getAlgorithm().getName())
        || !com.nimbusds.jose.EncryptionMethod.A256GCM.equals(
            parsed.getHeader().getEncryptionMethod())) {
      throw new InvalidOpenIdRequestException("response transport is out of profile");
    }
    // Overlap order: current key first, previous keys after. A kid
    // mismatch is not fatal — wallets may lag rotation — but every
    // key is tried before the response is refused.
    for (DecryptionKey key : decryptionKeys) {
      try {
        parsed.decrypt(new ECDHDecrypter(key.jwk()));
        Payload payload = parsed.getPayload();
        if (payload == null) {
          throw new InvalidOpenIdRequestException("response payload is empty");
        }
        return payload.toString();
      } catch (InvalidOpenIdRequestException e) {
        throw e;
      } catch (Exception e) {
        // Try the next overlap key.
      }
    }
    throw new InvalidOpenIdRequestException("response decryption failed");
  }

  @Override
  public Map<String, Object> jwks() {
    List<Map<String, Object>> keys = new ArrayList<>();
    keys.add(publicEntry(signingJwk, signingKid, "sig"));
    for (DecryptionKey key : decryptionKeys) {
      keys.add(publicEntry(key.jwk(), key.kid(), "enc"));
    }
    return Map.of("keys", keys);
  }

  private static Map<String, Object> publicEntry(ECKey jwk, String kid, String use) {
    Map<String, Object> entry = new LinkedHashMap<>();
    entry.put("kty", "EC");
    entry.put("crv", "P-256");
    entry.put("kid", kid);
    entry.put("use", use);
    entry.put("x", jwk.getX().toString());
    entry.put("y", jwk.getY().toString());
    return entry;
  }

  static ECKey load(Path path, String kid) {
    String pem;
    try {
      pem = Files.readString(path);
    } catch (Exception e) {
      throw new IllegalStateException("verifier key file is unreadable: " + path, e);
    }
    try {
      KeyFactory factory = KeyFactory.getInstance("EC");
      ECPrivateKey privateKey =
          (ECPrivateKey)
              factory.generatePrivate(
                  new PKCS8EncodedKeySpec(armor(pem, "PRIVATE KEY")));
      ECPublicKey publicKey =
          (ECPublicKey)
              factory.generatePublic(new X509EncodedKeySpec(armor(pem, "PUBLIC KEY")));
      return new ECKey.Builder(Curve.P_256, publicKey).privateKey(privateKey).keyID(kid).build();
    } catch (IllegalStateException e) {
      throw e;
    } catch (Exception e) {
      throw new IllegalStateException("verifier key file is not a P-256 keypair: " + path, e);
    }
  }

  private static byte[] armor(String pem, String label) {
    String begin = "-----BEGIN " + label + "-----";
    String end = "-----END " + label + "-----";
    int start = pem.indexOf(begin);
    int stop = pem.indexOf(end);
    if (start < 0 || stop < 0 || stop < start) {
      throw new IllegalStateException("PEM block missing: " + label);
    }
    String body = pem.substring(start + begin.length(), stop).replaceAll("\\s", "");
    try {
      return Base64.getDecoder().decode(body);
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException("PEM block is not base64: " + label, e);
    }
  }

  private static Path requirePath(String key, String value) {
    if (value == null || value.isBlank()) {
      throw new IllegalStateException(key + " must name a verifier key file");
    }
    return Path.of(value.trim());
  }

  private static String requireKid(String key, String kid) {
    if (kid == null || kid.isBlank() || kid.length() > 128) {
      throw new IllegalStateException(key + " must be a non-blank kid of at most 128 chars");
    }
    return kid.trim();
  }

  private static String[] splitList(String value) {
    if (value == null || value.isBlank()) {
      return new String[0];
    }
    return java.util.Arrays.stream(value.split(",")).map(String::trim).toArray(String[]::new);
  }
}
