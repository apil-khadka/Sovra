package dev.sovra.auth;

import dev.sovra.authz.Role;
import java.util.Set;
import java.util.UUID;

/**
 * Authenticated caller. The tenant always comes from the verified credential,
 * never from caller-supplied headers or parameters. Roles are the closed
 * {@link Role} set: unknown role strings can never reach authorization.
 */
public record ServiceAccountPrincipal(
    UUID id, UUID tenantId, String name, Set<Role> roles) {}
