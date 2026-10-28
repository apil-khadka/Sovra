package dev.sovra.auth;

import java.util.Collection;
import java.util.List;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/** Authenticated API-token identity. Carries no credentials after verification. */
public record ServiceAccountAuthentication(ServiceAccountPrincipal principal)
    implements Authentication {

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return List.of();
  }

  @Override
  public Object getCredentials() {
    return null;
  }

  @Override
  public Object getDetails() {
    return null;
  }

  @Override
  public Object getPrincipal() {
    return principal;
  }

  @Override
  public boolean isAuthenticated() {
    return true;
  }

  @Override
  public void setAuthenticated(boolean isAuthenticated) {
    if (!isAuthenticated) {
      throw new IllegalArgumentException("cannot unauthenticate");
    }
  }

  @Override
  public String getName() {
    return principal.name();
  }
}
