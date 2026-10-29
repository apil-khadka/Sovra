package dev.sovra.authz;

import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.auth.HumanMembershipRepository;
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
  static final long RULES_VERSION = 11;

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
          Map.entry(Action.VALIDATE_PLAN, Set.of("TENANT_MEMBER", "RP_CLIENT")),
          // Either tenant agent may request planning; the candidate is
          // untrusted until the guard accepts it, and planning tools are
          // read-only (SOV-013).
          Map.entry(Action.PROPOSE_PLAN, Set.of("TENANT_MEMBER", "RP_CLIENT")),
          // Alerts are global derived ops state; only audit and trust
          // administration roles review them (SOV-029).
          Map.entry(Action.READ_ALERTS, Set.of("AUDIT_READER", "TRUST_ADMIN")),
          // Telemetry summaries are tenant-scoped to the caller; members
          // may review their own flow timings and reason counts.
          Map.entry(
              Action.READ_TELEMETRY, Set.of("TENANT_MEMBER", "AUDIT_READER", "TRUST_ADMIN")),
          Map.entry(Action.RUN_CANARY, Set.of("TENANT_MEMBER", "AUDIT_READER", "TRUST_ADMIN")),
          Map.entry(Action.CREATE_SERVICE_ACCOUNT, Set.of("TRUST_ADMIN")),
          Map.entry(Action.READ_SERVICE_ACCOUNT, Set.of("TRUST_ADMIN")),
          Map.entry(Action.ROTATE_SERVICE_ACCOUNT, Set.of("TRUST_ADMIN")),
          Map.entry(Action.REVOKE_SERVICE_ACCOUNT, Set.of("TRUST_ADMIN")),
          // Vault (SOV-016): issuer workers ingest and grant; members
          // read only through a live grant; relying parties never see
          // source (INV-11); auditors see metadata, never content; key
          // lifecycle and deletion are trust administration.
          Map.entry(Action.VAULT_STORE_OBJECT, Set.of("ISSUER_OPS")),
          Map.entry(Action.VAULT_READ_OBJECT, Set.of("TENANT_MEMBER", "ISSUER_OPS")),
          Map.entry(
              Action.VAULT_READ_METADATA,
              Set.of("TENANT_MEMBER", "ISSUER_OPS", "AUDIT_READER", "TRUST_ADMIN")),
          Map.entry(Action.VAULT_GRANT_ACCESS, Set.of("ISSUER_OPS")),
          Map.entry(Action.VAULT_REVOKE_GRANT, Set.of("ISSUER_OPS", "TRUST_ADMIN")),
          Map.entry(Action.VAULT_ROTATE_KEK, Set.of("TRUST_ADMIN")),
          Map.entry(Action.VAULT_DELETE_VERSION, Set.of("TRUST_ADMIN")),
          // Quarantine (SOV-017): issuer-operated admission desk;
          // auditors and trust admins inspect verdicts, never bytes.
          Map.entry(Action.QUARANTINE_ADMIT, Set.of("ISSUER_OPS")),
          Map.entry(
              Action.QUARANTINE_READ, Set.of("ISSUER_OPS", "AUDIT_READER", "TRUST_ADMIN")),
          Map.entry(Action.QUARANTINE_PROMOTE, Set.of("ISSUER_OPS")),
          // OpenID4VCI (SOV-036): issuer operators publish offers; the
          // holder's tenant agent drives the synthetic authorization
          // server. Wallet token/credential calls carry no service
          // account and are bound to single-use grants instead.
          Map.entry(Action.VCI_CREATE_OFFER, Set.of("ISSUER_OPS")),
          Map.entry(Action.VCI_AUTHORIZE, Set.of("TENANT_MEMBER")),
          // OpenID4VP (SOV-036): the consuming relying party opens
          // the session; the wallet response is bound to the session
          // nonce and the verifier encryption key.
          Map.entry(Action.VP_CREATE_REQUEST, Set.of("RP_CLIENT")));

  private final ServiceAccountRepository accounts;
  private final HumanMembershipRepository humans;
  private final EmergencyFlagService emergency;
  private final PermissionCache cache;
  private final JdbcTemplate global;
  private final Clock clock;

  public AuthorizationService(
      ServiceAccountRepository accounts,
      HumanMembershipRepository humans,
      EmergencyFlagService emergency,
      PermissionCache cache,
      DataSource globalDataSource,
      Clock clock) {
    this.accounts = accounts;
    this.humans = humans;
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
    // Either credential store vouches: machine accounts and
    // provisioned human memberships share this liveness gate, so
    // revocation in either store denies on the next call.
    boolean live =
        accounts
            .findLive(principal.id())
            .map(row -> row.live(clock.instant()))
            .orElseGet(
                () -> humans.findLive(principal.id()).map(row -> row.live()).orElse(false));
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

  /** Epoch stamped on every decision and audit row. */
  public long policyVersion() {
    Long active =
        global.queryForObject(
            "SELECT COALESCE(MAX(snapshot_version), 0) FROM trust_snapshot_activation",
            Long.class);
    return RULES_VERSION * 1_000_000_000L + (active == null ? 0 : active);
  }
}
