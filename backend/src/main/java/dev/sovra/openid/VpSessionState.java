package dev.sovra.openid;

/**
 * VP session lifecycle. The closed set eliminates typo'd state
 * comparisons; the V16 {@code CHECK} enforces the same set at rest,
 * so unknown stored values are unreachable and fail loud.
 */
public enum VpSessionState {
  PENDING,
  COMPLETED,
  EXPIRED;

  /** Parses a stored state name, failing fast on unknown values. */
  public static VpSessionState from(String name) {
    try {
      return VpSessionState.valueOf(name);
    } catch (IllegalArgumentException | NullPointerException e) {
      throw new IllegalArgumentException("unknown vp session state: " + name);
    }
  }
}
