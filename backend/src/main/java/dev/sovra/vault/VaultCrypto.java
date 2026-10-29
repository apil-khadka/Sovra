package dev.sovra.vault;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Vault AEAD primitives (SOV-016): AES-256-GCM via the JDK, HKDF-SHA256
 * for synthetic KEK derivation, length-prefixed AAD framing. No state,
 * no caches: every call takes all key material as parameters and the
 * callers hold it only for the operation (SOV-004 DEK rule: zero
 * cross-request plaintext cache entries).
 */
public final class VaultCrypto {

  static final int GCM_NONCE_BYTES = 12;
  static final int GCM_TAG_BITS = 128;
  static final int DEK_BYTES = 32;

  private static final SecureRandom RANDOM = new SecureRandom();

  private VaultCrypto() {}

  /** Fresh random bytes. */
  public static byte[] randomBytes(int length) {
    byte[] raw = new byte[length];
    RANDOM.nextBytes(raw);
    return raw;
  }

  /** Fresh 256-bit data-encryption key. */
  public static byte[] freshDek() {
    return randomBytes(DEK_BYTES);
  }

  /** Fresh 96-bit GCM nonce. */
  public static byte[] freshNonce() {
    return randomBytes(GCM_NONCE_BYTES);
  }

  public static byte[] sha256(byte[] input) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(input);
    } catch (Exception e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  /**
   * RFC 5869 HKDF-SHA256 (extract with the given salt, expand with the
   * given info). Labels domain-separate every derivation.
   */
  public static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(salt, "HmacSHA256"));
      byte[] prk = mac.doFinal(ikm);
      byte[] output = new byte[length];
      byte[] previous = new byte[0];
      int filled = 0;
      int counter = 1;
      while (filled < length) {
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update(previous);
        mac.update(info);
        mac.update((byte) counter);
        previous = mac.doFinal();
        int take = Math.min(previous.length, length - filled);
        System.arraycopy(previous, 0, output, filled, take);
        filled += take;
        counter++;
      }
      return output;
    } catch (Exception e) {
      throw new IllegalStateException("HKDF-SHA256 unavailable", e);
    }
  }

  /** AES-256-GCM encrypt; AAD authenticated, never encrypted. */
  public static byte[] seal(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad) {
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(
          Cipher.ENCRYPT_MODE,
          new SecretKeySpec(key, "AES"),
          new GCMParameterSpec(GCM_TAG_BITS, nonce));
      cipher.updateAAD(aad);
      return cipher.doFinal(plaintext);
    } catch (Exception e) {
      throw new IllegalStateException("vault seal failed", e);
    }
  }

  /**
   * AES-256-GCM decrypt. Any ciphertext, tag, nonce, or AAD mismatch
   * throws {@link VaultAuthenticationException} with no partial
   * plaintext: JCE releases nothing before tag verification.
   */
  public static byte[] open(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad) {
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(
          Cipher.DECRYPT_MODE,
          new SecretKeySpec(key, "AES"),
          new GCMParameterSpec(GCM_TAG_BITS, nonce));
      cipher.updateAAD(aad);
      return cipher.doFinal(ciphertext);
    } catch (Exception e) {
      throw new VaultAuthenticationException("vault authentication failed");
    }
  }

  /**
   * Unambiguous AAD framing: label plus 2-byte big-endian
   * length-prefixed fields. Field splits can never be confused no
   * matter what the values contain.
   */
  public static byte[] frame(String label, byte[]... fields) {
    byte[] prefix = label.getBytes(StandardCharsets.UTF_8);
    int length = 2 + prefix.length;
    for (byte[] field : fields) {
      length += 2 + field.length;
    }
    byte[] framed = new byte[length];
    int at = 0;
    at = copyLengthPrefixed(framed, at, prefix);
    for (byte[] field : fields) {
      at = copyLengthPrefixed(framed, at, field);
    }
    return framed;
  }

  private static int copyLengthPrefixed(byte[] out, int at, byte[] field) {
    if (field.length > 65535) {
      throw new IllegalArgumentException("AAD field too long");
    }
    out[at] = (byte) (field.length >>> 8);
    out[at + 1] = (byte) field.length;
    System.arraycopy(field, 0, out, at + 2, field.length);
    return at + 2 + field.length;
  }
}
