package dev.sovra.auth;

import dev.sovra.audit.AuditService;
import dev.sovra.audit.AuditedAuthorizer;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ResourceRef;
import dev.sovra.authz.Role;
import java.time.Clock;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * RP-dashboard credential management (SOV-025): tenant agents
 * list, rotate, and revoke relying-party credentials without
 * trust administration. The RP app rule holds the boundary:
 * only accounts that bear {@code RP_CLIENT} without leaving
 * the RP subset are visible or touchable here, so issuer,
 * auditor, trust-admin, and fellow member credentials can
 * neither be enumerated nor disturbed through this path.
 */
@Service
public class RpCredentialService {

  static final Set<Role> RP_SUBSET = EnumSet.of(Role.RP_CLIENT, Role.TENANT_MEMBER);

  private final AuthorizationService authz;
  private final AuditService audit;
  private final ServiceAccountService accounts;
  private final JdbcTemplate tenant;
  private final Clock clock;

  public RpCredentialService(
      AuthorizationService authz,
      AuditService audit,
      ServiceAccountService accounts,
      JdbcTemplate tenantJdbcTemplate,
      Clock clock) {
    this.authz = authz;
    this.audit = audit;
    this.accounts = accounts;
    this.tenant = tenantJdbcTemplate;
    this.clock = clock;
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public List<ServiceAccountService.AccountView> apps(ServiceAccountPrincipal caller) {
    Decision decision =
        AuditedAuthorizer.require(authz, audit, caller, Action.MANAGE_RP_CREDENTIALS,
        ResourceRef.tenantScoped("rp-credential", "list", caller.tenantId()));
    List<ServiceAccountService.AccountView> items =
        tenant.query(
            "SELECT id, name, roles, revoked, expires_at, created_at FROM service_account"
                + " WHERE tenant_id = ? AND roles <@ ARRAY['RP_CLIENT','TENANT_MEMBER']::text[]"
                + " AND 'RP_CLIENT' = ANY (roles) ORDER BY created_at",
            accounts::mapRow,
            caller.tenantId());
    audit.record(
        caller,
        Action.MANAGE_RP_CREDENTIALS,
        ResourceRef.tenantScoped("rp-credential", "list", caller.tenantId()),
        decision,
        "",
        Map.of("count", String.valueOf(items.size())));
    return items;
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public ServiceAccountService.CreatedAccount rotate(
      ServiceAccountPrincipal caller, UUID id, Instant expiresAt) {
    ServiceAccountService.AccountView current = scoped(caller, id);
    Decision decision =
        AuditedAuthorizer.require(authz, audit, caller, Action.MANAGE_RP_CREDENTIALS,
        ResourceRef.tenantScoped("rp-credential", id.toString(), caller.tenantId()));
    if (expiresAt != null && !expiresAt.isAfter(clock.instant())) {
      throw new ServiceAccountService.InvalidServiceAccountException(
          "expiry must be in the future");
    }
    ServiceAccountService.CreatedAccount rotated =
        accounts.rotateToken(caller.tenantId(), id, current, expiresAt);
    audit.record(
        caller,
        Action.MANAGE_RP_CREDENTIALS,
        ResourceRef.tenantScoped("rp-credential", id.toString(), caller.tenantId()),
        Decision.permit(authz.policyVersion()),
        "rotate",
        Map.of("account_id", id.toString()));
    return rotated;
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public ServiceAccountService.AccountView revoke(ServiceAccountPrincipal caller, UUID id) {
    ServiceAccountService.AccountView current = scoped(caller, id);
    Decision decision =
        AuditedAuthorizer.require(authz, audit, caller, Action.MANAGE_RP_CREDENTIALS,
        ResourceRef.tenantScoped("rp-credential", id.toString(), caller.tenantId()));
    ServiceAccountService.AccountView revoked =
        accounts.revokeToken(caller.tenantId(), id, current);
    audit.record(
        caller,
        Action.MANAGE_RP_CREDENTIALS,
        ResourceRef.tenantScoped("rp-credential", id.toString(), caller.tenantId()),
        Decision.permit(authz.policyVersion()),
        "revoke",
        Map.of("account_id", id.toString()));
    return revoked;
  }

  /**
   * RP-app gate: accounts outside the RP subset, or inside it
   * without bearing {@code RP_CLIENT}, 404 exactly like
   * unknown ones, so this path never confirms or denies
   * issuer, trust, auditor, or fellow member accounts.
   */
  private ServiceAccountService.AccountView scoped(ServiceAccountPrincipal caller, UUID id) {
    ServiceAccountService.AccountView current = accounts.load(caller.tenantId(), id)
        .orElseThrow(ServiceAccountService.ServiceAccountNotFoundException::new);
    if (!RP_SUBSET.containsAll(current.roles()) || !current.roles().contains(Role.RP_CLIENT)) {
      throw new ServiceAccountService.ServiceAccountNotFoundException();
    }
    return current;
  }
}
