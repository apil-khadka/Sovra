package dev.sovra.web;

import dev.sovra.auth.ServiceAccountAuthentication;
import dev.sovra.auth.ServiceAccountPrincipal;
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
}
