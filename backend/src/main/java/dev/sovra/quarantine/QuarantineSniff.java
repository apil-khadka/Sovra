package dev.sovra.quarantine;

import java.util.Optional;

/**
 * Actual-type sniffing from magic bytes (SOV-017). Pure Java with no
 * dependencies so the isolated worker reuses the exact classifier the
 * admission desk applies. Claimed types are labels only; this verdict
 * governs admission, and the worker re-verifies it independently.
 */
public final class QuarantineSniff {

  private static final byte[] PNG_MAGIC = {
    (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
  };

  private QuarantineSniff() {}

  /**
   * Classifies bytes as {@code png}, {@code jpeg}, or empty when the
   * actual type is not allowlisted. JPEG detection requires the SOI
   * marker plus a JFIF/Exif APP0/APP1 segment or a second marker,
   * so bare {@code FFD8} prefixes alone do not pass.
   */
  public static Optional<String> actualType(byte[] content) {
    if (content == null || content.length < 4) {
      return Optional.empty();
    }
    if (startsWith(content, PNG_MAGIC)) {
      return Optional.of("png");
    }
    if ((content[0] & 0xFF) == 0xFF
        && (content[1] & 0xFF) == 0xD8
        && (content[2] & 0xFF) == 0xFF) {
      return Optional.of("jpeg");
    }
    return Optional.empty();
  }

  private static boolean startsWith(byte[] content, byte[] prefix) {
    if (content.length < prefix.length) {
      return false;
    }
    for (int i = 0; i < prefix.length; i++) {
      if (content[i] != prefix[i]) {
        return false;
      }
    }
    return true;
  }
}
