package dev.sovra.quarantine;

/** Admission not promotable (pending or rejected verdict); rendered as 409. */
public class QuarantineConflictException extends RuntimeException {

  public QuarantineConflictException(String message) {
    super(message);
  }
}
