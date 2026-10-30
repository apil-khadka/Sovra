package dev.sovra.enrollment;

/**
 * Unreviewed source, wrong lifecycle state, self-approval, or
 * stale revision; rendered as 409. Separation of duties and
 * revision currency are conflicts, never silent overrides.
 */
public class EnrollmentConflictException extends RuntimeException {

  public EnrollmentConflictException(String message) {
    super(message);
  }
}
