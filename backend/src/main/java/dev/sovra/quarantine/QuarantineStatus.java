package dev.sovra.quarantine;

/**
 * Quarantine admission lifecycle. The closed set eliminates typo'd
 * status comparisons; the V15 {@code CHECK} enforces the same set
 * at rest, so unknown stored values are unreachable and fail loud.
 */
public enum QuarantineStatus {
  QUARANTINED,
  SCANNING,
  CLEAN,
  REJECTED,
  PROMOTED;

  /** Parses a stored status name, failing fast on unknown values. */
  public static QuarantineStatus from(String name) {
    try {
      return QuarantineStatus.valueOf(name);
    } catch (IllegalArgumentException | NullPointerException e) {
      throw new IllegalArgumentException("unknown quarantine status: " + name);
    }
  }
}
