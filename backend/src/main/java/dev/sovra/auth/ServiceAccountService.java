package dev.sovra.auth;

import dev.sovra.audit.AuditService;
import dev.sovra.audit.AuditedAuthorizer;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.PermissionCache;
import dev.sovra.authz.ResourceRef;
import dev.sovra.authz.Role;
import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Application credential lifecycle (SOV-006): TRUST_ADMIN-managed
 * service accounts with one-time tokens, rotation, and terminal
 * revocation. Served on both chains — machine Bearer and BFF
 * session — over the shared principal: the transport differs, the
 * authority checks are identical. Tokens are shown once, hashed at
 * rest, and never written to audit detail.
 */
@Service
public class ServiceAccountService {

  public static class ServiceAccountNotFoundException extends RuntimeException {}

  public static class InvalidServiceAccountException extends RuntimeException {
    InvalidServiceAccountException(String message) {
      super(message);
    }
  }

  public static class ServiceAccountConflictException extends RuntimeException {
    ServiceAccountConflictException(String message) {
      super(message);
    }
  }

  public record AccountView(
      UUID id,
      String name,
      Set<Role> roles,
      boolean revoked,
      Instant expiresAt,
      Instant createdAt) {}

  public record CreatedAccount(AccountView account, String oneTimeToken) {}

  private final AuthorizationService authz;
  private final AuditService audit;
  private final PermissionCache cache;
  private final JdbcTemplate tenant;
  private final Clock clock;

  public ServiceAccountService(
      AuthorizationService authz,
      AuditService audit,
      PermissionCache cache,
      JdbcTemplate tenantJdbcTemplate,
      Clock clock) {
    this.authz = authz;
    this.audit = audit;
    this.cache = cache;
    this.tenant = tenantJdbcTemplate;
    this.clock = clock;
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public CreatedAccount create(
      ServiceAccountPrincipal caller, String name, Set<String> roles, Instant expiresAt) {
    Decision decision =
        AuditedAuthorizer.require(authz, audit, caller,
        Action.CREATE_SERVICE_ACCOUNT,
        ResourceRef.tenantScoped("service-account", "create", caller.tenantId()));
    validateName(name);
    Set<Role> granted = validateRoles(roles);
    if (expiresAt != null && !expiresAt.isAfter(clock.instant())) {
      throw new InvalidServiceAccountException("expiry must be in the future");
    }
    String token = TokenHasher.generate();
    UUID id = UUID.randomUUID();
    tenant.update(
        "INSERT INTO service_account (id, tenant_id, name, token_prefix, token_hash, roles,"
            + " expires_at) VALUES (?, ?, ?, ?, ?, ?::text[], ?)",
        id, caller.tenantId(), name.trim(), TokenHasher.prefix(token), TokenHasher.hash(token),
        granted.stream().map(Role::name).toArray(String[]::new), expiresAt == null ? null
            : java.sql.Timestamp.from(expiresAt));
    AccountView view = load(caller.tenantId(), id).orElseThrow();
    Map<String, String> detail = new LinkedHashMap<>();
    detail.put("account_id", id.toString());
    detail.put(
        "roles", String.join(",", granted.stream().map(Role::name).sorted().toList()));
    audit.record(
        caller, Action.CREATE_SERVICE_ACCOUNT,
        ResourceRef.tenantScoped("service-account", id.toString(), caller.tenantId()),
        Decision.permit(authz.policyVersion()), "", detail);
    return new CreatedAccount(view, token);
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public CreatedAccount rotate(ServiceAccountPrincipal caller, UUID id, Instant expiresAt) {
    AccountView current = load(caller.tenantId(), id)
        .orElseThrow(ServiceAccountNotFoundException::new);
    Decision decision =
        AuditedAuthorizer.require(authz, audit, caller,
        Action.ROTATE_SERVICE_ACCOUNT,
        ResourceRef.tenantScoped("service-account", id.toString(), caller.tenantId()));
    if (current.revoked()) {
      throw new ServiceAccountConflictException("revoked accounts stay revoked; create a new one");
    }
    if (expiresAt != null && !expiresAt.isAfter(clock.instant())) {
      throw new InvalidServiceAccountException("expiry must be in the future");
    }
    String token = TokenHasher.generate();
    tenant.update(
        "UPDATE service_account SET token_prefix = ?, token_hash = ?, expires_at = ?"
            + " WHERE id = ? AND tenant_id = ?",
        TokenHasher.prefix(token), TokenHasher.hash(token),
        expiresAt == null ? null : java.sql.Timestamp.from(expiresAt), id, caller.tenantId());
    cache.invalidatePrincipal(id);
    audit.record(
        caller, Action.ROTATE_SERVICE_ACCOUNT,
        ResourceRef.tenantScoped("service-account", id.toString(), caller.tenantId()),
        Decision.permit(authz.policyVersion()), "",
        Map.of("account_id", id.toString()));
    return new CreatedAccount(load(caller.tenantId(), id).orElseThrow(), token);
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public AccountView revoke(ServiceAccountPrincipal caller, UUID id) {
    AccountView current = load(caller.tenantId(), id)
        .orElseThrow(ServiceAccountNotFoundException::new);
    Decision decision =
        AuditedAuthorizer.require(authz, audit, caller,
        Action.REVOKE_SERVICE_ACCOUNT,
        ResourceRef.tenantScoped("service-account", id.toString(), caller.tenantId()));
    if (!current.revoked()) {
      tenant.update(
          "UPDATE service_account SET revoked = TRUE WHERE id = ? AND tenant_id = ?",
          id, caller.tenantId());
      cache.invalidatePrincipal(id);
    }
    audit.record(
        caller, Action.REVOKE_SERVICE_ACCOUNT,
        ResourceRef.tenantScoped("service-account", id.toString(), caller.tenantId()),
        Decision.permit(authz.policyVersion()), "",
        Map.of("account_id", id.toString()));
    return load(caller.tenantId(), id).orElseThrow();
  }

  public AccountView get(ServiceAccountPrincipal caller, UUID id) {
    AccountView current = load(caller.tenantId(), id)
        .orElseThrow(ServiceAccountNotFoundException::new);
    Decision decision =
        AuditedAuthorizer.require(authz, audit, caller,
        Action.READ_SERVICE_ACCOUNT,
        ResourceRef.tenantScoped("service-account", id.toString(), caller.tenantId()));
    return current;
  }

  public List<AccountView> list(ServiceAccountPrincipal caller) {
    Decision decision =
        AuditedAuthorizer.require(authz, audit, caller,
        Action.READ_SERVICE_ACCOUNT,
        ResourceRef.tenantScoped("service-account", "list", caller.tenantId()));
    return tenant.query(
        "SELECT id, name, roles, revoked, expires_at, created_at FROM service_account"
            + " WHERE tenant_id = ? ORDER BY created_at",
        this::mapRow,
        caller.tenantId());
  }

  private Optional<AccountView> load(UUID tenantId, UUID id) {
    List<AccountView> rows = tenant.query(
        "SELECT id, name, roles, revoked, expires_at, created_at FROM service_account"
            + " WHERE id = ? AND tenant_id = ?",
        this::mapRow,
        id, tenantId);
    return rows.stream().findFirst();
  }

  private AccountView mapRow(ResultSet rs, int row) throws SQLException {
    Array rolesArray = rs.getArray("roles");
    String[] roles = rolesArray == null ? new String[0] : (String[]) rolesArray.getArray();
    java.sql.Timestamp expires = rs.getTimestamp("expires_at");
    return new AccountView(
        rs.getObject("id", UUID.class),
        rs.getString("name"),
        Role.parseAll(roles),
        rs.getBoolean("revoked"),
        expires == null ? null : expires.toInstant(),
        rs.getTimestamp("created_at").toInstant());
  }

  private static void validateName(String name) {
    if (name == null || name.isBlank() || name.trim().length() > 128) {
      throw new InvalidServiceAccountException("name must be 1..128 chars");
    }
  }

  private static Set<Role> validateRoles(Set<String> roles) {
    if (roles == null || roles.isEmpty()) {
      throw new InvalidServiceAccountException("roles must be a non-empty known subset");
    }
    Set<Role> granted = new HashSet<>();
    for (String role : roles) {
      try {
        granted.add(Role.from(role));
      } catch (IllegalArgumentException e) {
        throw new InvalidServiceAccountException("roles must be a non-empty known subset");
      }
    }
    return granted;
  }

}
