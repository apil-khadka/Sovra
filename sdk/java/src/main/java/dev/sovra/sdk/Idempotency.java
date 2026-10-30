package dev.sovra.sdk;

import java.util.UUID;

/**
 * Idempotency-key helpers (SOV-021). Keys match the server
 * alphabet; a retry resends the same key and the server replays
 * the original response byte-for-byte instead of duplicating
 * work. Fresh operations mint fresh keys.
 */
public final class Idempotency {

  private Idempotency() {}

  /** Fresh random key in the server alphabet. */
  public static String mint() {
    return UUID.randomUUID().toString().replace("-", "");
  }

  /** True when the server would accept the key shape. */
  public static boolean valid(String key) {
    return key != null && key.matches("[A-Za-z0-9_-]{1,128}");
  }
}
