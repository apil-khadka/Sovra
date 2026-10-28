package dev.sovra.ops;

/** Semantic check outcome. Any non-UP check closes flow readiness. */
public enum CheckStatus {
  UP,
  DEGRADED,
  DOWN
}
