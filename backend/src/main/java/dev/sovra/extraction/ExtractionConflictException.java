package dev.sovra.extraction;

/**
 * Stale approval or duplicate run for one source version; rendered
 * as 409. Approving a superseded revision is a conflict, never a
 * silent rewind.
 */
public class ExtractionConflictException extends RuntimeException {

  public ExtractionConflictException(String message) {
    super(message);
  }
}
