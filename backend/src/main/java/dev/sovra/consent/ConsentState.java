package dev.sovra.consent;

/**
 * Proof-request lifecycle. The closed set eliminates typo'd state
 * comparisons; the V7 {@code CHECK} enforces the same set at rest,
 * so unknown stored values are unreachable and fail loud. Derived
 * view states ({@code VERIFIED}, {@code UNAVAILABLE}) are
 * presentation-only and stay strings at the view edge.
 */
public enum ConsentState {
  PENDING,
  APPROVED,
  DENIED;

  /** Parses a stored state name, failing fast on unknown values. */
  public static ConsentState from(String name) {
    try {
      return ConsentState.valueOf(name);
    } catch (IllegalArgumentException | NullPointerException e) {
      throw new IllegalArgumentException("unknown consent state: " + name);
    }
  }
}
