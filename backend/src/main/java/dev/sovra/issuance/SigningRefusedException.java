package dev.sovra.issuance;

/** The signer refused: unknown, revoked, or unauthorized key. Maps to 500. */
public class SigningRefusedException extends RuntimeException {

  public SigningRefusedException(String message) {
    super(message);
  }
}
