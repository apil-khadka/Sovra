package dev.sovra.quarantine;

/** Malformed admission request (shape, bounds, unknown actual type); rendered as 400. */
public class QuarantineInvalidException extends RuntimeException {

  public QuarantineInvalidException(String message) {
    super(message);
  }
}
