package dev.sovra.enrollment;

/** Malformed enrollment input or binding proof; rendered as 400. */
public class EnrollmentInvalidException extends RuntimeException {

  public EnrollmentInvalidException(String message) {
    super(message);
  }
}
