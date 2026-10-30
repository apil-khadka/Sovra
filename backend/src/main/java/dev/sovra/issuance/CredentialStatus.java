package dev.sovra.issuance;

/**
 * Stored credential standing. The closed set eliminates typo'd
 * status comparisons; the V6 {@code CHECK} enforces the same set
 * at rest, so unknown stored values are unreachable and fail loud.
 */
public enum CredentialStatus {
  VALID,
  REVOKED;

  /** Parses a stored status name, failing fast on unknown values. */
  public static CredentialStatus from(String name) {
    try {
      return CredentialStatus.valueOf(name);
    } catch (IllegalArgumentException | NullPointerException e) {
      throw new IllegalArgumentException("unknown credential status: " + name);
    }
  }
}
