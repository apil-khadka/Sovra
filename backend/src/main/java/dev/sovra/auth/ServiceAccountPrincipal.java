package dev.sovra.auth;

import dev.sovra.authz.Role;
import java.util.Set;
import java.util.UUID;

/**
 * Authenticated caller. The tenant always comes from the verified credential,
 * never from caller-supplied headers or parameters. Roles are the closed
 * {@link Role} set: unknown role strings can never reach authorization.
 * Human callers additionally carry their stable {@code (issuer, subject)}
 * binding; machine callers carry nulls. The binding is what lets quorum
 * rules tell two people apart from one person with two accounts.
 */
public record ServiceAccountPrincipal(
    UUID id, UUID tenantId, String name, Set<Role> roles, String issuer, String subject) {

  /** Machine callers carry no human binding. */
  public ServiceAccountPrincipal(UUID id, UUID tenantId, String name, Set<Role> roles) {
    this(id, tenantId, name, roles, null, null);
  }
}
