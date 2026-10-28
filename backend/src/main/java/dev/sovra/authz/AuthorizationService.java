package dev.sovra.authz;

import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.auth.ServiceAccountRepository;
import java.time.Clock;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Central authorization entry point. Every protected service method calls
 * {@link #authorize} explicitly; annotations are not used so no proxy or
 * self-invocation gap can skip the check. Credential validity (revoked /
 * expired) is rechecked live on every call; only the role/action decision
 * is cached, for 60 seconds keyed by policy version.
 */
@Service
public class AuthorizationService {

  /** Bump to invalidate every cached decision on rule changes. */
  static final long RULES_VERSION = 5;

  private static final Map<Action, Set<String>> REQUIRED_ROLES =
      Map.ofEntries(
          Map.entry(Action.ISSUE_CREDENTIAL, Set.of("ISSUER_OPS")),
          Map.entry(Action.READ_CREDENTIAL, Set.of("TENANT_MEMBER", "ISSUER_OPS")),
          Map.entry(Action.PROPOSE_TRUST_CHANGE, Set.of("TRUST_ADMIN")),
          Map.entry(Action.APPROVE_TRUST_CHANGE, Set.of("TRUST_ADMIN")),
          Map.entry(Action.ACTIVATE_TRUST_SNAPSHOT, Set.of("TRUST_ADMIN")),
          Map.entry(Action.READ_AUDIT, Set.of("AUDIT_READER", "TRUST_ADMIN")),
          Map.entry(Action.REQUEST_PROOF, Set.of("RP_CLIENT")),
          Map.entry(Action.READ_CONSENT, Set.of("TENANT_MEMBER", "RP_CLIENT")),
          // Transport authentication only: the holder key proof carries the
          // decision authority, so either tenant agent may deliver it.
          Map.entry(Action.DECIDE_CONSENT, Set.of("TENANT_MEMBER", "RP_CLIENT")),
          // Verification runs for the relying party that will consume the
          // decision; either tenant agent may retrieve a stored decision.
          Map.entry(Action.VERIFY_PRESENTATION, Set.of("RP_CLIENT")),
          Map.entry(Action.READ_VERIFICATION, Set.of("TENANT_MEMBER", "RP_CLIENT")),
          // Key lifecycle is trust administration. Registration alone
          // never widens trust — only a two-person snapshot activation
          // authorizes a new key — and revocation only narrows it.
          Map.entry(Action.REGISTER_ISSUER_KEY, Set.of("TRUST_ADMIN")),
          Map.entry(Action.REVOKE_ISSUER_KEY, Set.of("TRUST_ADMIN")),
          // Either tenant agent may validate a candidate plan; the
          // verdict authorizes nothing by itself (INV-05).
          Map.entry(Action.VALIDATE_PLAN, Set.of("TENANT_MEMBER", "RP_CLIENT")));

  private final ServiceAccountRepository accounts;
  private final EmergencyFlagService emergency;
  private final PermissionCache cache;
  private final JdbcTemplate global;
  private final Clock clock;

  public AuthorizationService(
      ServiceAccountRepository accounts,
      EmergencyFlagService emergency,
      PermissionCache cache,
      DataSource globalDataSource,
      Clock clock) {
    this.accounts = accounts;
    this.emergency = emergency;
    this.cache = cache;
    this.global = new JdbcTemplate(globalDataSource);
    this.clock = clock;
  }

  /**
   * Authorizes the action or throws {@link ForbiddenException} /
   * {@link TenantMismatchException}. Returns the auditable decision.
   */
  public Decision authorize(
      Optional<ServiceAccountPrincipal> caller, Action action, ResourceRef resource) {
    long policyVersion = policyVersion();
    if (emergency.enabled()) {
      return Decision.deny(ReasonCode.EMERGENCY_FREEZE, policyVersion);
    }
    if (caller.isEmpty()) {
      return Decision.deny(ReasonCode.ANONYMOUS, policyVersion);
    }
    ServiceAccountPrincipal principal = caller.get();
    boolean live =
        accounts
            .findLive(principal.id())
            .map(row -> row.live(clock.instant()))
            .orElse(false);
    if (!live) {
      cache.invalidatePrincipal(principal.id());
      return Decision.deny(ReasonCode.CREDENTIAL_REVOKED, policyVersion);
    }
    if (resource.tenantId().isPresent()
        && !resource.tenantId().get().equals(principal.tenantId())) {
      return Decision.deny(ReasonCode.WRONG_TENANT, policyVersion);
    }
    Decision cached = cache.get(principal.id(), action, resource, policyVersion);
    if (cached != null) {
      return cached;
    }
    Decision decision = decide(principal, action, policyVersion);
    cache.put(principal.id(), action, resource, policyVersion, decision);
    return decision;
  }

  /** Authorizes and throws the HTTP-mapped exception on denial. */
  public void enforce(
      Optional<ServiceAccountPrincipal> caller, Action action, ResourceRef resource) {
    Decision decision = authorize(caller, action, resource);
    if (decision.permitted()) {
      return;
    }
    if (decision.reasonCode() == ReasonCode.WRONG_TENANT) {
      throw new TenantMismatchException();
    }
    throw new ForbiddenException(decision.reasonCode());
  }

  private Decision decide(ServiceAccountPrincipal principal, Action action, long policyVersion) {
    Set<String> required = REQUIRED_ROLES.get(action);
    if (required == null) {
      return Decision.deny(ReasonCode.MISSING_ROLE, policyVersion);
    }
    for (String role : principal.roles()) {
      if (required.contains(role)) {
        return Decision.permit(policyVersion);
      }
    }
    return Decision.deny(ReasonCode.MISSING_ROLE, policyVersion);
  }

  private long policyVersion() {
    Long active =
        global.queryForObject(
            "SELECT COALESCE(MAX(snapshot_version), 0) FROM trust_snapshot_activation",
            Long.class);
    return RULES_VERSION * 1_000_000_000L + (active == null ? 0 : active);
  }
}
