package dev.sovra.tenancy;

import dev.sovra.auth.ServiceAccountPrincipal;
import java.util.Optional;

/**
 * Request-scoped authenticated caller, bound by the auth filter and cleared
 * at request end. Service code reads identity only from here.
 */
public final class TenantContext {

  private static final ThreadLocal<ServiceAccountPrincipal> CURRENT = new ThreadLocal<>();

  private TenantContext() {}

  public static void set(ServiceAccountPrincipal principal) {
    CURRENT.set(principal);
  }

  public static Optional<ServiceAccountPrincipal> current() {
    return Optional.ofNullable(CURRENT.get());
  }

  /** Fails closed when no authenticated principal is bound. */
  public static ServiceAccountPrincipal require() {
    ServiceAccountPrincipal principal = CURRENT.get();
    if (principal == null) {
      throw new TenantRequiredException("no authenticated tenant in context");
    }
    return principal;
  }

  public static void clear() {
    CURRENT.remove();
  }

  /**
   * Runs work as the given principal, restoring the empty context
   * after. For service code that acts outside a request (wallet
   * callbacks resolving their creator); request filters own their
   * lifecycle directly instead.
   */
  public static void with(ServiceAccountPrincipal principal, Runnable work) {
    set(principal);
    try {
      work.run();
    } finally {
      clear();
    }
  }

  /** Result-bearing variant of {@link #with}. */
  public static <T> T withResult(
      ServiceAccountPrincipal principal, java.util.function.Supplier<T> work) {
    set(principal);
    try {
      return work.get();
    } finally {
      clear();
    }
  }
}
