package dev.sovra.guard;

import java.util.List;

/**
 * Per-type attestable-claim allowlists, delegating to the shared versioned
 * {@link ApprovedSchemas} registry. Kept as the historic entry point so
 * existing callers keep working; new code should use the registry directly
 * for type-specific and semantic checks.
 */
public final class GuardClaims {

  private GuardClaims() {}

  public static List<String> forType(String vct) {
    return ApprovedSchemas.forType(vct);
  }
}
