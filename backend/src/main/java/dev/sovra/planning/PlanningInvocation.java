package dev.sovra.planning;

import dev.sovra.auth.ServiceAccountPrincipal;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The authorized caller plus the per-request tool budget for one
 * planning invocation (SOV-013, SR-08). The planning service installs
 * it around the model call; every tool callback reads it back to
 * reauthorize the live caller and charge the budget. Tool callbacks
 * run on the calling thread, so a plain {@link ThreadLocal} suffices;
 * anything outside an installed invocation fails closed.
 */
public final class PlanningInvocation {

  private static final ThreadLocal<PlanningInvocation> CURRENT = new ThreadLocal<>();

  private final ServiceAccountPrincipal caller;
  private final AtomicInteger usedCalls = new AtomicInteger();
  private final int maxToolCalls;
  private final java.util.List<String> scopeIssuerIds;
  private final java.util.List<String> scopeCredentialTypes;
  private final java.util.List<String> scopeJurisdictions;

  public PlanningInvocation(ServiceAccountPrincipal caller, int maxToolCalls) {
    this(caller, maxToolCalls, java.util.List.of(), java.util.List.of(), java.util.List.of());
  }

  public PlanningInvocation(
      ServiceAccountPrincipal caller,
      int maxToolCalls,
      java.util.List<String> scopeIssuerIds,
      java.util.List<String> scopeCredentialTypes,
      java.util.List<String> scopeJurisdictions) {
    this.caller = caller;
    this.maxToolCalls = maxToolCalls;
    this.scopeIssuerIds = scopeIssuerIds == null ? java.util.List.of() : java.util.List.copyOf(scopeIssuerIds);
    this.scopeCredentialTypes = scopeCredentialTypes == null
        ? java.util.List.of() : java.util.List.copyOf(scopeCredentialTypes);
    this.scopeJurisdictions = scopeJurisdictions == null
        ? java.util.List.of() : java.util.List.copyOf(scopeJurisdictions);
  }

  /** Discovery scope narrowing this invocation; empty lists mean unscoped. */
  public java.util.List<String> scopeIssuerIds() {
    return scopeIssuerIds;
  }

  public java.util.List<String> scopeCredentialTypes() {
    return scopeCredentialTypes;
  }

  public java.util.List<String> scopeJurisdictions() {
    return scopeJurisdictions;
  }

  /** True when any scope list narrows visible metadata. */
  public boolean scoped() {
    return !scopeIssuerIds.isEmpty() || !scopeCredentialTypes.isEmpty()
        || !scopeJurisdictions.isEmpty();
  }

  /** Installs the invocation for the current thread; caller must clear it. */
  public static void install(PlanningInvocation invocation) {
    CURRENT.set(invocation);
  }

  /** Removes the current thread's invocation. */
  public static void clear() {
    CURRENT.remove();
  }

  /** The live invocation, or empty outside an authorized planning call. */
  public static Optional<PlanningInvocation> current() {
    return Optional.ofNullable(CURRENT.get());
  }

  public ServiceAccountPrincipal caller() {
    return caller;
  }

  public int usedCalls() {
    return usedCalls.get();
  }

  /**
   * Charges one tool call against the budget (SEC-16, SEC-19). The
   * model can neither see nor reset the counter; exhaustion ends the
   * run as unavailable instead of inventing evidence.
   */
  public void charge() {
    if (usedCalls.incrementAndGet() > maxToolCalls) {
      throw new PlanningUnavailableException(
          "planning tool budget exceeded; no candidate produced");
    }
  }
}
