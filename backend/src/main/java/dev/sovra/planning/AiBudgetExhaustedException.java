package dev.sovra.planning;

/**
 * A live-AI reservation was denied (PROD-012): daily request/token
 * budget exhausted or fleet concurrency full. Callers surface
 * planning-unavailable; the denial itself is evidence, logged with
 * the limiting dimension.
 */
public class AiBudgetExhaustedException extends RuntimeException {

  public AiBudgetExhaustedException(String message) {
    super(message);
  }
}
