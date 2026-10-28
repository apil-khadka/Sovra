package dev.sovra.issuance;

/** Malformed or unauthorized issuance request. Maps to 400. */
public class InvalidIssuanceException extends RuntimeException {

  public InvalidIssuanceException(String message) {
    super(message);
  }
}
