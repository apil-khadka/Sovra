package dev.sovra.consent;

/** A malformed, unbound, expired, or otherwise unusable consent request. Maps to a 400. */
public class InvalidConsentException extends RuntimeException {

  public InvalidConsentException(String message) {
    super(message);
  }
}
