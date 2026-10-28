package dev.sovra.vault;

/** Malformed vault request (shape, bounds, unknown purpose/workload); rendered as 400. */
public class VaultInvalidException extends RuntimeException {

  public VaultInvalidException(String message) {
    super(message);
  }
}
