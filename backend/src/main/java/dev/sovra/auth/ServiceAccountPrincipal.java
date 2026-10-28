package dev.sovra.auth;

import java.util.Set;
import java.util.UUID;

/**
 * Authenticated caller. The tenant always comes from the verified credential,
 * never from caller-supplied headers or parameters.
 */
public record ServiceAccountPrincipal(
    UUID id, UUID tenantId, String name, Set<String> roles) {}
