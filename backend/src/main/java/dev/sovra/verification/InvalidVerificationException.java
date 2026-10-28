package dev.sovra.verification;

/** A verification submission whose envelope is malformed. Maps to 400. */
public class InvalidVerificationException extends RuntimeException {
  public InvalidVerificationException(String message) {
    super(message);
  }
}
