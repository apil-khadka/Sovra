package dev.sovra.authz;

import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.auth.HumanMembershipRepository;
import dev.sovra.auth.ServiceAccountRepository;
import java.time.Clock;
import java.util.EnumSet;
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

  private static final Map<Action, Set<Role>> REQUIRED_ROLES =
      Map.ofEntries(
          Map.entry(Action.ISSUE_CREDENTIAL, EnumSet.of(Role.ISSUER_OPS)),
          Map.entry(Action.READ_CREDENTIAL, EnumSet.of(Role.TENANT_MEMBER, Role.ISSUER_OPS)),
          Map.entry(Action.PROPOSE_TRUST_CHANGE, EnumSet.of(Role.TRUST_ADMIN)),
          Map.entry(Action.APPROVE_TRUST_CHANGE, EnumSet.of(Role.TRUST_ADMIN)),
          Map.entry(Action.ACTIVATE_TRUST_SNAPSHOT, EnumSet.of(Role.TRUST_ADMIN)),
          Map.entry(Action.READ_AUDIT, EnumSet.of(Role.AUDIT_READER, Role.TRUST_ADMIN)),
          Map.entry(Action.REQUEST_PROOF, EnumSet.of(Role.RP_CLIENT)),
          Map.entry(Action.READ_CONSENT, EnumSet.of(Role.TENANT_MEMBER, Role.RP_CLIENT)),
          // Transport authentication only: the holder key proof carries the
          // decision authority, so either tenant agent may deliver it.
          Map.entry(Action.DECIDE_CONSENT, EnumSet.of(Role.TENANT_MEMBER, Role.RP_CLIENT)),
          // Verification runs for the relying party that will consume the
          // decision; either tenant agent may retrieve a stored decision.
          Map.entry(Action.VERIFY_PRESENTATION, EnumSet.of(Role.RP_CLIENT)),
          Map.entry(Action.READ_VERIFICATION, EnumSet.of(Role.TENANT_MEMBER, Role.RP_CLIENT)),
          // Key lifecycle is trust administration. Registration alone
          // never widens trust — only a two-person snapshot activation
          // authorizes a new key — and revocation only narrows it.
          Map.entry(Action.REGISTER_ISSUER_KEY, EnumSet.of(Role.TRUST_ADMIN)),
          Map.entry(Action.REVOKE_ISSUER_KEY, EnumSet.of(Role.TRUST_ADMIN)),
          // Either tenant agent may validate a candidate plan; the
          // verdict authorizes nothing by itself (INV-05).
          Map.entry(Action.VALIDATE_PLAN, EnumSet.of(Role.TENANT_MEMBER, Role.RP_CLIENT)),
          // Either tenant agent may request planning; the candidate is
          // untrusted until the guard accepts it, and planning tools are
          // read-only (SOV-013).
          Map.entry(Action.PROPOSE_PLAN, EnumSet.of(Role.TENANT_MEMBER, Role.RP_CLIENT)),
          // Alerts are global derived ops state; only audit and trust
          // administration roles review them (SOV-029).
          Map.entry(Action.READ_ALERTS, EnumSet.of(Role.AUDIT_READER, Role.TRUST_ADMIN)),
          // Telemetry summaries are tenant-scoped to the caller; members
          // may review their own flow timings and reason counts.
          Map.entry(
              Action.READ_TELEMETRY, EnumSet.of(Role.TENANT_MEMBER, Role.AUDIT_READER, Role.TRUST_ADMIN)),
          Map.entry(Action.RUN_CANARY, EnumSet.of(Role.TENANT_MEMBER, Role.AUDIT_READER, Role.TRUST_ADMIN)),
          Map.entry(Action.CREATE_SERVICE_ACCOUNT, EnumSet.of(Role.TRUST_ADMIN)),
          Map.entry(Action.READ_SERVICE_ACCOUNT, EnumSet.of(Role.TRUST_ADMIN)),
          Map.entry(Action.ROTATE_SERVICE_ACCOUNT, EnumSet.of(Role.TRUST_ADMIN)),
          Map.entry(Action.REVOKE_SERVICE_ACCOUNT, EnumSet.of(Role.TRUST_ADMIN)),
          // Vault (SOV-016): issuer workers ingest and grant; members
          // read only through a live grant; relying parties never see
          // source (INV-11); auditors see metadata, never content; key
          // lifecycle and deletion are trust administration.
          Map.entry(Action.VAULT_STORE_OBJECT, EnumSet.of(Role.ISSUER_OPS)),
          Map.entry(Action.VAULT_READ_OBJECT, EnumSet.of(Role.TENANT_MEMBER, Role.ISSUER_OPS)),
          Map.entry(
              Action.VAULT_READ_METADATA,
              EnumSet.of(Role.TENANT_MEMBER, Role.ISSUER_OPS, Role.AUDIT_READER, Role.TRUST_ADMIN)),
          Map.entry(Action.VAULT_GRANT_ACCESS, EnumSet.of(Role.ISSUER_OPS)),
          Map.entry(Action.VAULT_REVOKE_GRANT, EnumSet.of(Role.ISSUER_OPS, Role.TRUST_ADMIN)),
          Map.entry(Action.VAULT_ROTATE_KEK, EnumSet.of(Role.TRUST_ADMIN)),
          Map.entry(Action.VAULT_DELETE_VERSION, EnumSet.of(Role.TRUST_ADMIN)),
          // Quarantine (SOV-017): issuer-operated admission desk;
          // auditors and trust admins inspect verdicts, never bytes.
          Map.entry(Action.QUARANTINE_ADMIT, EnumSet.of(Role.ISSUER_OPS)),
          Map.entry(
              Action.QUARANTINE_READ, EnumSet.of(Role.ISSUER_OPS, Role.AUDIT_READER, Role.TRUST_ADMIN)),
          Map.entry(Action.QUARANTINE_PROMOTE, EnumSet.of(Role.ISSUER_OPS)),
          // Extraction (SOV-018): operators run, correct, and
          // approve; reads follow the quarantine read set.
          Map.entry(Action.EXTRACTION_RUN, EnumSet.of(Role.ISSUER_OPS)),
          Map.entry(Action.EXTRACTION_CORRECT, EnumSet.of(Role.ISSUER_OPS)),
          Map.entry(Action.EXTRACTION_APPROVE, EnumSet.of(Role.ISSUER_OPS)),
          Map.entry(
              Action.EXTRACTION_READ,
              EnumSet.of(Role.ISSUER_OPS, Role.AUDIT_READER, Role.TRUST_ADMIN)),
          // Enrollment (SOV-019, OD-14): operators run the case
          // lifecycle; reads follow the extraction read set.
          // Maker/checker separation is enforced by identity
          // comparison in the service, not by role.
          Map.entry(Action.ENROLLMENT_CREATE, EnumSet.of(Role.ISSUER_OPS)),
          Map.entry(Action.ENROLLMENT_SUBMIT, EnumSet.of(Role.ISSUER_OPS)),
          Map.entry(Action.ENROLLMENT_DECIDE, EnumSet.of(Role.ISSUER_OPS)),
          Map.entry(
              Action.ENROLLMENT_READ,
              EnumSet.of(Role.ISSUER_OPS, Role.AUDIT_READER, Role.TRUST_ADMIN)),
          // Holder custody (SOV-020, OD-09): operators report loss,
          // but only trust admins complete a recovery.
          Map.entry(Action.HOLDER_REPORT, EnumSet.of(Role.ISSUER_OPS)),
          Map.entry(Action.HOLDER_RECOVER, EnumSet.of(Role.TRUST_ADMIN)),
          Map.entry(
              Action.HOLDER_READ,
              EnumSet.of(Role.ISSUER_OPS, Role.AUDIT_READER, Role.TRUST_ADMIN)),
          // Issuer desk (SOV-023): operators read their own
          // casework trail (extraction/enrollment/issuance/vault/
          // quarantine actions only); the full audit stays with
          // auditors and trust admins.
          Map.entry(
              Action.READ_ISSUER_AUDIT,
              EnumSet.of(Role.ISSUER_OPS, Role.AUDIT_READER, Role.TRUST_ADMIN)),
          // Holder dashboard (SOV-024): members read only the
          // cases, disclosures, credentials, and recovery bound
          // to a holder key they just proved in-session. The
          // session unlock — never a caller parameter — selects
          // the thumbprint, so no person-search oracle exists.
          Map.entry(Action.HOLDER_READ_SELF, EnumSet.of(Role.TENANT_MEMBER)),
          // OpenID4VCI (SOV-036): issuer operators publish offers; the
          // holder's tenant agent drives the synthetic authorization
          // server. Wallet token/credential calls carry no service
          // account and are bound to single-use grants instead.
          Map.entry(Action.VCI_CREATE_OFFER, EnumSet.of(Role.ISSUER_OPS)),
          Map.entry(Action.VCI_AUTHORIZE, EnumSet.of(Role.TENANT_MEMBER)),
          // OpenID4VP (SOV-036): the consuming relying party opens
          // the session; the wallet response is bound to the session
          // nonce and the verifier encryption key.
          Map.entry(Action.VP_CREATE_REQUEST, EnumSet.of(Role.RP_CLIENT)));

  /**
   * Actions that never pass through authorization: login and logout
   * exist before/around the session and are audit events with
   * locally-built decisions, not authorization checks. They carry no
   * map entry, and {@code decide} still denies them if misrouted.
   */
  private static final Set<Action> AUDIT_ONLY_ACTIONS =
      EnumSet.of(Action.BFF_LOGIN, Action.BFF_LOGOUT);

  static {
    assertRulesComplete();
  }

  /**
   * Fails fast when an action is neither ruled nor declared audit-only,
   * so a new {@link Action} can never ship with an unwritten rule. The
   * runtime null-guard in {@code decide} stays as defense in depth.
   */
  static void assertRulesComplete() {
    for (Action action : Action.values()) {
      boolean ruled = REQUIRED_ROLES.containsKey(action);
      boolean auditOnly = AUDIT_ONLY_ACTIONS.contains(action);
      if (ruled == auditOnly) {
        throw new IllegalStateException(
            "action must be ruled or audit-only, exclusively: " + action);
      }
    }
  }

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
   * Authorizes the action, returning the auditable decision (never
   * throwing for denials). Callers that refuse must record the denial;
   * {@code dev.sovra.audit.AuditedAuthorizer} is the entry that does
   * both, so silent denials are unrepresentable.
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

  private Decision decide(ServiceAccountPrincipal principal, Action action, long policyVersion) {
    Set<Role> required = REQUIRED_ROLES.get(action);
    if (required == null) {
      return Decision.deny(ReasonCode.MISSING_ROLE, policyVersion);
    }
    for (Role role : principal.roles()) {
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
