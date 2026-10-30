package dev.sovra.vault;

/**
 * Stored vault-object-version standing. The closed set eliminates
 * typo'd status comparisons; the V14 {@code CHECK} enforces the
 * same set at rest, so unknown stored values are unreachable and
 * fail loud.
 */
public enum VaultObjectStatus {
  VALID,
  DELETED,
  PURGED;

  /** Parses a stored status name, failing fast on unknown values. */
  public static VaultObjectStatus from(String name) {
    try {
      return VaultObjectStatus.valueOf(name);
    } catch (IllegalArgumentException | NullPointerException e) {
      throw new IllegalArgumentException("unknown vault object status: " + name);
    }
  }
}
