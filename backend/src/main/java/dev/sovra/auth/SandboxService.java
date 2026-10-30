package dev.sovra.auth;

import dev.sovra.audit.AuditService;
import dev.sovra.audit.AuditedAuthorizer;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.authz.ResourceRef;
import dev.sovra.authz.Role;
import java.time.Clock;
import java.time.Duration;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Developer-portal sandbox onboarding (SOV-022): members mint
 * fixed-shape relying-party credentials for the synthetic
 * sandbox — always {@code RP_CLIENT}, always expiring in 24
 * hours, always name-prefixed, and only on demo profiles. No
 * privilege choice exists to misconfigure, and production
 * profiles refuse outright, so the sandbox/production boundary
 * holds by construction.
 */
@Service
public class SandboxService {

  static final String NAME_PREFIX = "sandbox-";
  static final Set<Role> SANDBOX_ROLES = EnumSet.of(Role.RP_CLIENT);
  static final Duration SANDBOX_TTL = Duration.ofHours(24);
  static final Set<String> DEMO_PROFILES = Set.of("synthetic", "sdjwt-vc");

  private final AuthorizationService authz;
  private final AuditService audit;
  private final ServiceAccountService accounts;
  private final JdbcTemplate tenant;
  private final Clock clock;
  private final String profile;

  public SandboxService(
      AuthorizationService authz,
      AuditService audit,
      ServiceAccountService accounts,
      JdbcTemplate tenantJdbcTemplate,
      Clock clock,
      @Value("${sovra.profile:synthetic}") String profile) {
    this.authz = authz;
    this.audit = audit;
    this.accounts = accounts;
    this.tenant = tenantJdbcTemplate;
    this.clock = clock;
    this.profile = profile;
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public ServiceAccountService.CreatedAccount createSandbox(
      ServiceAccountPrincipal caller, String name) {
    Decision decision =
        AuditedAuthorizer.require(authz, audit, caller, Action.CREATE_SANDBOX_ACCOUNT,
        ResourceRef.tenantScoped("sandbox-account", "create", caller.tenantId()));
    if (!DEMO_PROFILES.contains(profile)) {
      throw new ForbiddenException(ReasonCode.SANDBOX_DEMO_ONLY);
    }
    String clean = name == null ? "" : name.trim().toLowerCase();
    if (!clean.startsWith(NAME_PREFIX)
        || clean.length() > 64
        || !clean.matches("sandbox-[a-z0-9]([a-z0-9-]*[a-z0-9])?")) {
      throw new ServiceAccountService.InvalidServiceAccountException(
          "sandbox names look like sandbox-my-app");
    }
    ServiceAccountService.CreatedAccount created = accounts.insertAccount(
        caller.tenantId(), clean, SANDBOX_ROLES, clock.instant().plus(SANDBOX_TTL));
    audit.record(
        caller,
        Action.CREATE_SANDBOX_ACCOUNT,
        ResourceRef.tenantScoped(
            "sandbox-account", created.account().id().toString(), caller.tenantId()),
        Decision.permit(authz.policyVersion()),
        "",
        Map.of("account_id", created.account().id().toString(), "roles", "RP_CLIENT"));
    return created;
  }

  /** Sandbox-prefixed accounts in this tenant; token material never leaves. */
  @Transactional(noRollbackFor = ForbiddenException.class)
  public List<ServiceAccountService.AccountView> listSandbox(ServiceAccountPrincipal caller) {
    Decision decision =
        AuditedAuthorizer.require(authz, audit, caller, Action.MANAGE_RP_CREDENTIALS,
        ResourceRef.tenantScoped("sandbox-account", "list", caller.tenantId()));
    List<ServiceAccountService.AccountView> items =
        tenant.query(
            "SELECT id, name, roles, revoked, expires_at, created_at FROM service_account"
                + " WHERE tenant_id = ? AND name LIKE 'sandbox-%' ORDER BY created_at",
            accounts::mapRow,
            caller.tenantId());
    audit.record(
        caller,
        Action.MANAGE_RP_CREDENTIALS,
        ResourceRef.tenantScoped("sandbox-account", "list", caller.tenantId()),
        decision,
        "",
        Map.of("count", String.valueOf(items.size())));
    return items;
  }
}
