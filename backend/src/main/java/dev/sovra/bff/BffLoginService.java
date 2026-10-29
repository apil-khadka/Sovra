package dev.sovra.bff;

import dev.sovra.audit.AuditService;
import dev.sovra.auth.HumanMembershipRepository;
import dev.sovra.auth.HumanMembershipRepository.MembershipRow;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.PermissionCache;
import dev.sovra.authz.ReasonCode;
import dev.sovra.authz.ResourceRef;
import dev.sovra.authz.Role;
import dev.sovra.tenancy.TenantContext;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * OIDC login decision (SOV-006). Exact issuer and audience matching
 * first — nothing from the token is trusted until both pass — then
 * tenant allowlisting, group-to-role mapping with unmapped groups
 * dropped, and hardware-bound-AMR gating for privileged roles. The
 * membership row is the provisioned credential; role changes evict
 * cached grants immediately.
 *
 * <p>Audit boundary: the audit schema is tenant-attributed, so
 * failures before tenant resolution are log-only (no secrets), while
 * everything after resolves to an audit row.
 */
@Service
public class BffLoginService {

  private static final Logger log = LoggerFactory.getLogger(BffLoginService.class);

  public static final String SESSION_MEMBERSHIP = "sovra.membershipId";
  public static final String SESSION_AMR = "sovra.amr";
  public static final String SESSION_AUTH_TIME = "sovra.authTime";
  public static final String SESSION_ID_TOKEN = "sovra.idToken";

  /** Carries the provisioned principal plus what the session must hold. */
  public record LoginResult(
      ServiceAccountPrincipal principal, List<String> amr, Instant authTime, String idToken) {}

  /** Denial with its audit-safe reason; the handler turns it into a redirect. */
  public static class BffLoginDeniedException extends RuntimeException {
    private final ReasonCode reasonCode;

    BffLoginDeniedException(ReasonCode reasonCode, String message) {
      super(message);
      this.reasonCode = reasonCode;
    }

    public ReasonCode reasonCode() {
      return reasonCode;
    }
  }

  private final AuthorizationService authz;
  private final BffProperties properties;
  private final HumanMembershipRepository memberships;
  private final PermissionCache cache;
  private final AuditService audit;
  private final JdbcTemplate global;

  public BffLoginService(
      AuthorizationService authz,
      BffProperties properties,
      HumanMembershipRepository memberships,
      PermissionCache cache,
      AuditService audit,
      DataSource globalDataSource) {
    this.authz = authz;
    this.properties = properties;
    this.memberships = memberships;
    this.cache = cache;
    this.audit = audit;
    this.global = new JdbcTemplate(globalDataSource);
  }

  // Denial evidence must survive the denial: the exception that
  // carries the reason never rolls back the audit row written for
  // it. (Denial paths write nothing else except a harmless
  // display/role sync on already-revoked rows.)
  @Transactional(noRollbackFor = BffLoginDeniedException.class)
  public LoginResult login(OidcUser user) {
    String issuer = user.getIssuer() == null ? "" : user.getIssuer().toString();
    String subject = user.getSubject();
    if (!properties.issuer().equals(issuer)) {
      log.warn("BFF login denied: untrusted issuer");
      throw new BffLoginDeniedException(ReasonCode.UNTRUSTED_ISSUER, "untrusted issuer");
    }
    if (subject == null || subject.isBlank()) {
      log.warn("BFF login denied: token without subject");
      throw new BffLoginDeniedException(ReasonCode.UNTRUSTED_ISSUER, "token without subject");
    }
    List<String> audiences = user.getAudience();
    if (audiences == null || !audiences.contains(properties.clientId())) {
      log.warn("BFF login denied: audience mismatch");
      throw new BffLoginDeniedException(ReasonCode.UNTRUSTED_ISSUER, "audience mismatch");
    }
    String tenantSlug = user.getClaimAsString(properties.tenantClaim());
    UUID tenantId = resolveTenant(tenantSlug);
    if (tenantId == null) {
      log.warn("BFF login denied: unknown tenant claim");
      throw new BffLoginDeniedException(ReasonCode.WRONG_TENANT, "unknown tenant");
    }
    // Tenant known from here: every outcome below is an audit row.
    ServiceAccountPrincipal sessionAnchor =
        new ServiceAccountPrincipal(uuidAnchor(), tenantId, subject, Set.of());
    TenantContext.set(sessionAnchor);
    try {
      return loginAttributed(user, issuer, subject, tenantId);
    } finally {
      TenantContext.clear();
    }
  }

  private LoginResult loginAttributed(OidcUser user, String issuer, String subject, UUID tenantId) {
    Set<Role> mapped = mapRoles(user);
    if (mapped.isEmpty()) {
      denyAttributed(tenantId, issuer, subject, ReasonCode.MISSING_ROLE, "no mapped roles", Map.of());
      throw new BffLoginDeniedException(ReasonCode.MISSING_ROLE, "no mapped roles");
    }
    List<String> amr = user.getClaimAsStringList("amr");
    amr = amr == null ? List.of() : List.copyOf(amr);
    Set<Role> conferred = conferRoles(mapped, amr);
    if (conferred.isEmpty()) {
      denyAttributed(tenantId, issuer, subject, ReasonCode.ASSURANCE_INSUFFICIENT,
          "privileged roles need hardware-bound authentication",
          Map.of("withheld_roles", joinNames(mapped)));
      throw new BffLoginDeniedException(
          ReasonCode.ASSURANCE_INSUFFICIENT, "hardware-bound authentication required");
    }
    String displayName = user.getClaimAsString("preferred_username");
    displayName = displayName == null || displayName.isBlank() ? subject : displayName;
    MembershipRow before = memberships.findBySubject(issuer, subject).orElse(null);
    MembershipRow stored = memberships.upsert(tenantId, issuer, subject, displayName, conferred);
    if (stored.revoked()) {
      denyAttributed(tenantId, issuer, subject, ReasonCode.CREDENTIAL_REVOKED,
          "membership revoked", Map.of());
      throw new BffLoginDeniedException(ReasonCode.CREDENTIAL_REVOKED, "membership revoked");
    }
    if (before != null && !before.roles().equals(stored.roles())) {
      cache.invalidatePrincipal(stored.id());
    }
    Instant authTime = authClaimTime(user);
    Map<String, String> detail = new LinkedHashMap<>();
    detail.put("subject_ref", issuer + "|" + subject);
    detail.put("roles", joinNames(conferred));
    Set<Role> withheld = new LinkedHashSet<>(mapped);
    withheld.removeAll(conferred);
    if (!withheld.isEmpty()) {
      detail.put("withheld_roles", joinNames(withheld));
    }
    audit.record(
        stored.principal(),
        Action.BFF_LOGIN,
        ResourceRef.tenantScoped("bff-session", stored.id().toString(), tenantId),
        Decision.permit(authz.policyVersion()),
        "",
        detail);
    String idToken = user.getIdToken() == null ? "" : user.getIdToken().getTokenValue();
    return new LoginResult(stored.principal(), amr, authTime, idToken);
  }

  private static String joinNames(Set<Role> roles) {
    return String.join(",", roles.stream().map(Role::name).toList());
  }

  private void denyAttributed(UUID tenantId, String issuer, String subject, ReasonCode reason,
      String message, Map<String, String> detail) {
    Map<String, String> full = new LinkedHashMap<>(detail);
    full.put("subject_ref", issuer + "|" + subject);
    full.put("message", message);
    audit.recordExternal(
        "oidc_subject",
        tenantId,
        issuer + "|" + subject,
        Action.BFF_LOGIN,
        ResourceRef.tenantScoped("bff-session", "denied", tenantId),
        Decision.deny(reason, authz.policyVersion()),
        "",
        full);
  }

  private Set<Role> mapRoles(OidcUser user) {
    List<String> groups = user.getClaimAsStringList(properties.groupsClaim());
    Set<Role> mapped = new LinkedHashSet<>();
    if (groups != null) {
      for (String group : groups) {
        Role role = properties.groupRoleMap().get(group);
        if (role != null) {
          mapped.add(role);
        }
      }
    }
    return mapped;
  }

  private Set<Role> conferRoles(Set<Role> mapped, List<String> amr) {
    boolean hardware = amr.stream().anyMatch(properties.hardwareAmr()::contains);
    Set<Role> conferred = new LinkedHashSet<>();
    for (Role role : mapped) {
      if (properties.privilegedRoles().contains(role) && !hardware) {
        continue;
      }
      conferred.add(role);
    }
    return conferred;
  }

  private UUID resolveTenant(String slug) {
    if (slug == null || !properties.allowedTenantSlugs().contains(slug)) {
      return null;
    }
    List<UUID> rows =
        global.query(
            "SELECT id FROM tenant WHERE slug = ?",
            (rs, row) -> rs.getObject("id", UUID.class),
            slug);
    return rows.stream().findFirst().orElse(null);
  }

  private static Instant authClaimTime(OidcUser user) {
    Object claim = user.getClaim("auth_time");
    if (claim instanceof Instant at) {
      return at;
    }
    if (claim instanceof Number epoch) {
      return Instant.ofEpochSecond(epoch.longValue());
    }
    return Instant.now();
  }

  private static UUID uuidAnchor() {
    return UUID.fromString("00000000-0000-0000-0000-000000000000");
  }
}
