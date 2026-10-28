package dev.sovra.authz;

import java.util.Optional;
import java.util.UUID;

/**
 * Authorization target. Tenant-scoped resources carry their tenant so the
 * service can distinguish cross-tenant access (reported as not found)
 * from forbidden access (reported as forbidden).
 */
public record ResourceRef(String type, String id, Optional<UUID> tenantId) {

  public static ResourceRef global(String type, String id) {
    return new ResourceRef(type, id, Optional.empty());
  }

  public static ResourceRef tenantScoped(String type, String id, UUID tenantId) {
    return new ResourceRef(type, id, Optional.of(tenantId));
  }
}
