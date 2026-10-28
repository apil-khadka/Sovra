package dev.sovra.vault;

import java.util.UUID;

/**
 * Wrapping-key operations (SOV-004 section 3, SOV-016). The interface
 * wraps and unwraps DEKs without ever exposing KEK bytes, matching
 * the KMS shape: the G2 provider swaps the implementation, and no
 * caller changes. Synthetic calls fail closed through the same
 * exceptions production uses.
 */
public interface VaultKekProvider {

  /** Wrapped DEK plus the wrap nonce. */
  record WrappedDek(byte[] wrapped, byte[] nonce) {}

  WrappedDek wrapDek(UUID tenantId, int kekVersion, byte[] dek, byte[] aad);

  /**
   * Unwraps a DEK or throws {@link VaultAuthenticationException};
   * provider outages throw
   * {@link dev.sovra.issuance.KmsUnavailableException} instead, never
   * a fallback value.
   */
  byte[] unwrapDek(UUID tenantId, int kekVersion, byte[] wrapped, byte[] nonce, byte[] aad);
}
