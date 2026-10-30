package dev.sovra.custody;

/** Live holder-key states. Mirrors the SQL CHECK. */
public enum HolderKeyStatus {
  ACTIVE,
  COMPROMISED;

  /** Fails fast on values outside the CHECK, instead of defaulting. */
  public static HolderKeyStatus from(String raw) {
    for (HolderKeyStatus status : values()) {
      if (status.name().equals(raw)) {
        return status;
      }
    }
    throw new IllegalStateException("unknown holder key status: " + raw);
  }
}
