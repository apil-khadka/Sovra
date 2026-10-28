package dev.sovra.guard;

/** Deterministic guard decision over a candidate plan. */
public record GuardVerdict(boolean accepted, GuardOutcome code, String reason) {

  public static GuardVerdict accept() {
    return new GuardVerdict(true, GuardOutcome.GUARD_ACCEPTED, null);
  }

  public static GuardVerdict reject(GuardOutcome code, String reason) {
    return new GuardVerdict(false, code, reason);
  }
}
