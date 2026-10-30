package dev.sovra.extraction;

/** Wrong source, bad schema, or malformed correction; rendered as 400. */
public class ExtractionInvalidException extends RuntimeException {

  public ExtractionInvalidException(String message) {
    super(message);
  }
}
