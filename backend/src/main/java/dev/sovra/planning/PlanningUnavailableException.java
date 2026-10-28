package dev.sovra.planning;

/**
 * Live planning dependency unavailable (SOV-013, FR-12). Dynamic planning
 * has no result; previously approved fixed flows are unaffected. Maps to
 * 503 with an explicit retryable problem detail, never a faked success.
 */
public class PlanningUnavailableException extends RuntimeException {

  public PlanningUnavailableException(String message) {
    super(message);
  }

  public PlanningUnavailableException(String message, Throwable cause) {
    super(message, cause);
  }
}
