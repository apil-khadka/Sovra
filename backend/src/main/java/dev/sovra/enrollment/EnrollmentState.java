package dev.sovra.enrollment;

/**
 * Enrollment lifecycle states. Mirrors the SQL CHECK: PENDING (just
 * created), IN_REVIEW (submitted for checker decision), APPROVED
 * (head revision reviewed, eligible while the source stays
 * current), REJECTED (terminal; a new enrollment starts over).
 */
public enum EnrollmentState {
  PENDING,
  IN_REVIEW,
  APPROVED,
  REJECTED;

  /** Fails fast on values outside the CHECK, instead of defaulting. */
  public static EnrollmentState from(String raw) {
    for (EnrollmentState state : values()) {
      if (state.name().equals(raw)) {
        return state;
      }
    }
    throw new IllegalStateException("unknown enrollment state: " + raw);
  }
}
