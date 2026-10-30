package dev.sovra.vault;

/**
 * Vault KEK standing. The closed set eliminates typo'd status
 * literals in KEK selection; the V14 {@code CHECK} enforces the
 * same set at rest.
 */
public enum KekStatus {
  ACTIVE,
  RETIRED;

  /** Parses a stored status name, failing fast on unknown values. */
  public static KekStatus from(String name) {
    try {
      return KekStatus.valueOf(name);
    } catch (IllegalArgumentException | NullPointerException e) {
      throw new IllegalArgumentException("unknown kek status: " + name);
    }
  }
}
