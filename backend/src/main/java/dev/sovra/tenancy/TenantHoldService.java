package dev.sovra.tenancy;

import dev.sovra.audit.AuditService;
import dev.sovra.audit.AuditedAuthorizer;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ResourceRef;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Legal-hold register (PROD-010). A hold suspends destruction for
 * a tenant — vault delete/purge refuse and the audit archival job
 * skips the tenant's rows — while protocol-state purges continue.
 * Setting and releasing are trust-admin platform powers, audited
 * with the target tenant in the detail.
 */
@Service
public class TenantHoldService {

  public static class TenantHoldNotFoundException extends RuntimeException {
    TenantHoldNotFoundException() {
      super("tenant is unknown");
    }
  }

  public record HoldView(UUID tenantId, String slug, boolean legalHold) {}

  private final AuthorizationService authz;
  private final AuditService audit;
  private final JdbcTemplate tenant;

  public TenantHoldService(
      AuthorizationService authz, AuditService audit, JdbcTemplate tenantJdbcTemplate) {
    this.authz = authz;
    this.audit = audit;
    this.tenant = tenantJdbcTemplate;
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public HoldView setHold(ServiceAccountPrincipal caller, UUID tenantId, boolean held) {
    Decision decision =
        AuditedAuthorizer.require(authz, audit, caller,
            Action.TENANT_SET_HOLD,
            ResourceRef.tenantScoped("tenant", tenantId.toString(), caller.tenantId()));
    int updated =
        tenant.update(
            "UPDATE tenant SET legal_hold = ? WHERE id = ?", held, tenantId);
    if (updated == 0) {
      throw new TenantHoldNotFoundException();
    }
    audit.record(
        caller, Action.TENANT_SET_HOLD,
        ResourceRef.tenantScoped("tenant", tenantId.toString(), caller.tenantId()),
        decision, "", Map.of("held", String.valueOf(held)));
    return load(tenantId);
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public List<HoldView> list(ServiceAccountPrincipal caller) {
    Decision decision =
        AuditedAuthorizer.require(authz, audit, caller,
            Action.TENANT_READ_HOLD,
            ResourceRef.tenantScoped("tenant", "holds", caller.tenantId()));
    List<HoldView> views =
        tenant.query(
            "SELECT id, slug, legal_hold FROM tenant ORDER BY slug",
            (rs, n) -> new HoldView(
                rs.getObject("id", UUID.class),
                rs.getString("slug"),
                rs.getBoolean("legal_hold")));
    audit.record(
        caller, Action.TENANT_READ_HOLD,
        ResourceRef.tenantScoped("tenant", "holds", caller.tenantId()),
        decision, "", Map.of("count", String.valueOf(views.size())));
    return views;
  }

  private HoldView load(UUID tenantId) {
    List<HoldView> rows =
        tenant.query(
            "SELECT id, slug, legal_hold FROM tenant WHERE id = ?",
            (rs, n) -> new HoldView(
                rs.getObject("id", UUID.class),
                rs.getString("slug"),
                rs.getBoolean("legal_hold")),
            tenantId);
    if (rows.isEmpty()) {
      throw new TenantHoldNotFoundException();
    }
    return rows.get(0);
  }
}
