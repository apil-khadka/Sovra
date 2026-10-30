package dev.sovra.vault;

/** Vault state conflicts (purge before delete): 409, not 400 — the shape is fine, the standing is not. */
public class VaultConflictException extends RuntimeException {
  public VaultConflictException(String message) {
    super(message);
  }
}
