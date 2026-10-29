package dev.sovra.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/** Opaque API-token hashing and generation. Tokens are shown once at creation. */
public final class TokenHasher {

  public static final String PREFIX = "sovra_test_";
  private static final int PREFIX_LEN = 8;
  private static final int SECRET_BYTES = 32;
  private static final SecureRandom RANDOM = new SecureRandom();

  private TokenHasher() {}

  /** Generates a new token; only the hash is stored. */
  public static String generate() {
    byte[] secret = new byte[SECRET_BYTES];
    RANDOM.nextBytes(secret);
    return PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
  }

  /** First {@value #PREFIX_LEN} chars of the encoded secret, for indexed lookup. */
  public static String prefix(String token) {
    String body = body(token);
    return body.substring(0, Math.min(PREFIX_LEN, body.length()));
  }

  public static byte[] hash(String token) {
    try {
      return MessageDigest.getInstance("SHA-256")
          .digest(token.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  public static boolean matches(String token, byte[] expectedHash) {
    if (token == null || !token.startsWith(PREFIX)) {
      return false;
    }
    return MessageDigest.isEqual(hash(token), expectedHash);
  }

  private static String body(String token) {
    if (token == null || !token.startsWith(PREFIX)) {
      return "";
    }
    return token.substring(PREFIX.length());
  }
}
