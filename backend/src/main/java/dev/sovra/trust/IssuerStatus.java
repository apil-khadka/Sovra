package dev.sovra.trust;

/**
 * Registry issuer standing. The closed set eliminates typo'd
 * status comparisons; the V4 {@code CHECK} enforces the same set
 * at rest, so unknown stored values are unreachable and fail loud.
 */
public enum IssuerStatus {
  ACTIVE,
  SUSPENDED,
  REVOKED;

  /** Parses a stored status name, failing fast on unknown values. */
  public static IssuerStatus from(String name) {
    try {
      return IssuerStatus.valueOf(name);
    } catch (IllegalArgumentException | NullPointerException e) {
      throw new IllegalArgumentException("unknown issuer status: " + name);
    }
  }
}
