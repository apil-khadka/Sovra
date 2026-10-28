package dev.sovra.guard;

/**
 * Candidate plan rejected by the guard; mapped to 400. Consent creation
 * throws this before any holder request exists.
 */
public class GuardRejectedException extends RuntimeException {

  private final GuardOutcome outcome;

  public GuardRejectedException(GuardOutcome outcome) {
    super("candidate plan rejected by the guard");
    this.outcome = outcome;
  }

  public GuardOutcome outcome() {
    return outcome;
  }
}
