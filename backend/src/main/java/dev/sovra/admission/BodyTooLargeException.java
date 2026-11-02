package dev.sovra.admission;

/** Request body exceeded the ingress byte budget. Maps to 413. */
public class BodyTooLargeException extends RuntimeException {

  public BodyTooLargeException() {
    super("request body too large");
  }
}
