package dev.sovra.extraction;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Protected value digests (OD-15, SR-23/24): SHA-256 over the
 * UTF-8 canonical bytes ({@code canon-v1}) and over the UTF-8
 * observed string, per field. Digests are integrity references
 * inside authorized reads, never lookup keys.
 */
public final class FieldDigests {

  public static final String CANON_ID = "canon-v1";

  private FieldDigests() {}

  public static byte[] sha256(byte[] input) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(input);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is mandatory", e);
    }
  }

  /** Digest over the canonical field bytes (canon-v1). */
  public static byte[] canonical(String normalized) {
    return sha256(normalized.getBytes(StandardCharsets.UTF_8));
  }

  /** Digest over the observed string, unmodified. */
  public static byte[] exact(String observed) {
    return sha256(observed.getBytes(StandardCharsets.UTF_8));
  }
}
