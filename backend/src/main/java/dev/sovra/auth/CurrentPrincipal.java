package dev.sovra.auth;

import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import java.util.Optional;
import org.springframework.security.core.context.SecurityContextHolder;

/** Reads the verified caller; empty for anonymous requests. */
public final class CurrentPrincipal {

  private CurrentPrincipal() {}

  public static Optional<ServiceAccountPrincipal> get() {
    var authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication instanceof ServiceAccountAuthentication serviceAuth) {
      return Optional.of(serviceAuth.principal());
    }
    return Optional.empty();
  }

  /** The verified caller, or 403 ANONYMOUS for anonymous requests. */
  public static ServiceAccountPrincipal require() {
    return get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
  }
}
