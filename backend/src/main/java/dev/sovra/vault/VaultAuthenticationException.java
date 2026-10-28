package dev.sovra.vault;

/**
 * AEAD open failure: ciphertext, tag, nonce, context, or key mismatch.
 * Carries no detail by design — substitution probes learn nothing —
 * and releases no plaintext (JCE verifies before output).
 */
public class VaultAuthenticationException extends RuntimeException {

  public VaultAuthenticationException(String message) {
    super(message);
  }
}
