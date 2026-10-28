package dev.sovra.ops;

/**
 * One flow-readiness dependency probe. Implementations must test the actual
 * dependency (query, freshness window, or rollback-only write) rather than
 * a cached flag, must never throw, and must never leak dependency internals
 * into the result detail.
 */
public interface ReadinessCheck {

  /** Stable snake_case check name used in reports and alert derivation. */
  String name();

  CheckResult check();
}
