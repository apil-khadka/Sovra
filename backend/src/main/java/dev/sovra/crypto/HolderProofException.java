package dev.sovra.crypto;

/** A holder key or proof-of-possession that fails shape or signature checks. */
public class HolderProofException extends RuntimeException {

  public HolderProofException(String message) {
    super(message);
  }

  public HolderProofException(String message, Throwable cause) {
    super(message, cause);
  }
}
