package dev.sovra.trust;

/**
 * Issuer signing-key standing. The closed set eliminates typo'd
 * status comparisons; the V21 {@code CHECK} enforces the same set
 * at rest, so unknown stored values are unreachable and fail loud.
 */
public enum KeyStatus {
  ACTIVE,
  REVOKED;

  /** Parses a stored status name, failing fast on unknown values. */
  public static KeyStatus from(String name) {
    try {
      return KeyStatus.valueOf(name);
    } catch (IllegalArgumentException | NullPointerException e) {
      throw new IllegalArgumentException("unknown key status: " + name);
    }
  }
}
