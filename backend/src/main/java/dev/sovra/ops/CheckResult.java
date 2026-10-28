package dev.sovra.ops;

import java.util.Map;

/**
 * One semantic readiness check result. The detail map carries fixed codes
 * and numbers only — never exception text, SQL, secrets, or identity data —
 * so the public readiness probe is safe to expose.
 */
public record CheckResult(
    String name, CheckStatus status, String code, Map<String, Object> detail, long durationMs) {

  public CheckResult {
    detail = Map.copyOf(detail);
    if (durationMs < 0) {
      durationMs = 0;
    }
  }

  public static CheckResult up(String name, String code, Map<String, Object> detail, long durationMs) {
    return new CheckResult(name, CheckStatus.UP, code, detail, durationMs);
  }

  public static CheckResult degraded(
      String name, String code, Map<String, Object> detail, long durationMs) {
    return new CheckResult(name, CheckStatus.DEGRADED, code, detail, durationMs);
  }

  public static CheckResult down(
      String name, String code, Map<String, Object> detail, long durationMs) {
    return new CheckResult(name, CheckStatus.DOWN, code, detail, durationMs);
  }
}
