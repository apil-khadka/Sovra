package dev.sovra.vault;

/** Destruction refused: the owning tenant is under legal hold. */
public class VaultLegalHoldException extends RuntimeException {
  VaultLegalHoldException(String message) {
    super(message);
  }
}
