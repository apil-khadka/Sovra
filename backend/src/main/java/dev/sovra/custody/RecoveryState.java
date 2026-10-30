package dev.sovra.custody;

/** Recovery-case states. Mirrors the SQL CHECK. */
public enum RecoveryState {
  REPORTED,
  RECOVERED;

  /** Fails fast on values outside the CHECK, instead of defaulting. */
  public static RecoveryState from(String raw) {
    for (RecoveryState state : values()) {
      if (state.name().equals(raw)) {
        return state;
      }
    }
    throw new IllegalStateException("unknown recovery state: " + raw);
  }
}
