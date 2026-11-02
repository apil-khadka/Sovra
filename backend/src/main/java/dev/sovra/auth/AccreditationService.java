package dev.sovra.auth;

import dev.sovra.audit.AuditService;
import dev.sovra.audit.AuditedAuthorizer;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ResourceRef;
import dev.sovra.authz.Role;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Accredited RP onboarding (PROD-015). Production RP credentials
 * arrive only through a reviewed accreditation: an operator requests
 * with exact roles, origins, and audiences, a trust admin approves —
 * stepped-up on the interactive path — and the approval mints a
 * bound, expiring bearer credential. Rejection and revocation close
 * the loop; the credential dies with the accreditation.
 */
@Service
public class AccreditationService {

  public static class InvalidAccreditationException extends RuntimeException {
    InvalidAccreditationException(String message) {
      super(message);
    }
  }

  public static class AccreditationConflictException extends RuntimeException {
    AccreditationConflictException(String message) {
      super(message);
    }
  }

  public static class AccreditationNotFoundException extends RuntimeException {
    AccreditationNotFoundException() {
      super("accreditation is unknown");
    }
  }

  static final Set<Role> ACCREDITABLE = EnumSet.of(Role.RP_CLIENT, Role.TENANT_MEMBER);

  static final java.time.Duration DEFAULT_CREDENTIAL_LIFETIME = java.time.Duration.ofDays(365);

  public record AccreditationView(
      UUID id,
      String orgName,
      Set<String> roles,
      List<String> origins,
      List<String> audiences,
      String state,
      String requestedBy,
      String decidedBy,
      Instant decidedAt,
      UUID credentialId,
      Instant createdAt) {}

  public record Approved(AccreditationView accreditation, String oneTimeToken) {}

  private final AuthorizationService authz;
  private final AuditService audit;
  private final ServiceAccountService accounts;
  private final JdbcTemplate tenant;
  private final Clock clock;

  public AccreditationService(
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
  public AccreditationView request(
      ServiceAccountPrincipal caller,
      String orgName,
      Set<String> roles,
      List<String> origins,
      List<String> audiences) {
    Decision decision =
        AuditedAuthorizer.require(authz, audit, caller,
            Action.ACCREDIT_REQUEST,
            ResourceRef.tenantScoped("accreditation", "request", caller.tenantId()));
    if (orgName == null || orgName.isBlank() || orgName.strip().length() > 128) {
      throw new InvalidAccreditationException("organization name is required");
    }
    Set<Role> granted = validateRoles(roles);
    List<String> cleanOrigins = validateOrigins(origins);
    List<String> cleanAudiences = validateAudiences(audiences);
    UUID id = UUID.randomUUID();
    tenant.update(
        "INSERT INTO accreditation (id, tenant_id, org_name, roles, origins, audiences,"
            + " requested_by) VALUES (?, ?, ?, ?::text[], ?::text[], ?::text[], ?)",
        id, caller.tenantId(), orgName.strip(),
        granted.stream().map(Role::name).toArray(String[]::new),
        cleanOrigins.toArray(String[]::new),
        cleanAudiences.toArray(String[]::new),
        caller.name());
    audit.record(
        caller, Action.ACCREDIT_REQUEST,
        ResourceRef.tenantScoped("accreditation", id.toString(), caller.tenantId()),
        decision, "", Map.of("org", orgName.strip()));
    return load(caller.tenantId(), id);
  }

  /**
   * Approval mints the bound credential: exact roles, exact origins
   * and audiences, bounded lifetime. The interactive entry point
   * enforces step-up before reaching here; this method enforces the
   * role and the forward-only state machine.
   */
  @Transactional(noRollbackFor = ForbiddenException.class)
  public Approved approve(ServiceAccountPrincipal caller, UUID id, Instant expiresAt) {
    Decision decision =
        AuditedAuthorizer.require(authz, audit, caller,
            Action.ACCREDIT_DECIDE,
            ResourceRef.tenantScoped("accreditation", id.toString(), caller.tenantId()));
    AccreditationView current = load(caller.tenantId(), id);
    if (!"REQUESTED".equals(current.state())) {
      throw new AccreditationConflictException("accreditation is already decided");
    }
    Instant expiry = expiresAt == null ? clock.instant().plus(DEFAULT_CREDENTIAL_LIFETIME)
        : expiresAt;
    if (!expiry.isAfter(clock.instant())) {
      throw new InvalidAccreditationException("credential expiry must be in the future");
    }
    Set<Role> granted = Role.parseAll(current.roles().toArray(String[]::new));
    ServiceAccountService.CreatedAccount created =
        accounts.insertAccount(
            caller.tenantId(),
            "accredited-" + slug(current.orgName()) + "-"
                + UUID.randomUUID().toString().substring(0, 8),
            granted,
            expiry);
    tenant.update(
        "UPDATE service_account SET allowed_origins = ?::text[], allowed_audiences = ?::text[]"
            + " WHERE id = ?",
        current.origins().toArray(String[]::new),
        current.audiences().toArray(String[]::new),
        created.account().id());
    tenant.update(
        "UPDATE accreditation SET state = 'APPROVED', decided_by = ?, decided_at = now(),"
            + " credential_id = ? WHERE id = ?",
        caller.name(), created.account().id(), id);
    Map<String, String> detail = new LinkedHashMap<>();
    detail.put("credential_id", created.account().id().toString());
    detail.put("roles", String.join(",", current.roles().stream().sorted().toList()));
    audit.record(
        caller, Action.ACCREDIT_DECIDE,
        ResourceRef.tenantScoped("accreditation", id.toString(), caller.tenantId()),
        decision, "", detail);
    return new Approved(load(caller.tenantId(), id), created.oneTimeToken());
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public AccreditationView reject(ServiceAccountPrincipal caller, UUID id) {
    Decision decision =
        AuditedAuthorizer.require(authz, audit, caller,
            Action.ACCREDIT_DECIDE,
            ResourceRef.tenantScoped("accreditation", id.toString(), caller.tenantId()));
    AccreditationView current = load(caller.tenantId(), id);
    if (!"REQUESTED".equals(current.state())) {
      throw new AccreditationConflictException("accreditation is already decided");
    }
    tenant.update(
        "UPDATE accreditation SET state = 'REJECTED', decided_by = ?, decided_at = now()"
            + " WHERE id = ?",
        caller.name(), id);
    audit.record(
        caller, Action.ACCREDIT_DECIDE,
        ResourceRef.tenantScoped("accreditation", id.toString(), caller.tenantId()),
        decision, "", Map.of("outcome", "rejected"));
    return load(caller.tenantId(), id);
  }

  /**
   * Revocation kills the credential with the accreditation: the
   * bearer stops authenticating immediately, and the state machine
   * never leaves REVOKED.
   */
  @Transactional(noRollbackFor = ForbiddenException.class)
  public AccreditationView revoke(ServiceAccountPrincipal caller, UUID id) {
    Decision decision =
        AuditedAuthorizer.require(authz, audit, caller,
            Action.ACCREDIT_DECIDE,
            ResourceRef.tenantScoped("accreditation", id.toString(), caller.tenantId()));
    AccreditationView current = load(caller.tenantId(), id);
    if (!"APPROVED".equals(current.state()) || current.credentialId() == null) {
      throw new AccreditationConflictException("accreditation is not revocable");
    }
    accounts.revoke(caller, current.credentialId());
    tenant.update(
        "UPDATE accreditation SET state = 'REVOKED', decided_by = ?, decided_at = now()"
            + " WHERE id = ?",
        caller.name(), id);
    audit.record(
        caller, Action.ACCREDIT_DECIDE,
        ResourceRef.tenantScoped("accreditation", id.toString(), caller.tenantId()),
        decision, "", Map.of("outcome", "revoked"));
    return load(caller.tenantId(), id);
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public AccreditationView get(ServiceAccountPrincipal caller, UUID id) {
    Decision decision =
        AuditedAuthorizer.require(authz, audit, caller,
            Action.ACCREDIT_READ,
            ResourceRef.tenantScoped("accreditation", id.toString(), caller.tenantId()));
    AccreditationView view = load(caller.tenantId(), id);
    audit.record(
        caller, Action.ACCREDIT_READ,
        ResourceRef.tenantScoped("accreditation", id.toString(), caller.tenantId()),
        decision, "", Map.of("state", view.state()));
    return view;
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public List<AccreditationView> list(ServiceAccountPrincipal caller) {
    Decision decision =
        AuditedAuthorizer.require(authz, audit, caller,
            Action.ACCREDIT_READ,
            ResourceRef.tenantScoped("accreditation", "list", caller.tenantId()));
    List<AccreditationView> views =
        tenant.query(
            "SELECT id, org_name, roles, origins, audiences, state, requested_by, decided_by,"
                + " decided_at, credential_id, created_at FROM accreditation"
                + " WHERE tenant_id = ? ORDER BY created_at",
            (rs, n) -> mapRow(rs),
            caller.tenantId());
    audit.record(
        caller, Action.ACCREDIT_READ,
        ResourceRef.tenantScoped("accreditation", "list", caller.tenantId()),
        decision, "", Map.of("count", String.valueOf(views.size())));
    return views;
  }

  private Set<Role> validateRoles(Set<String> roles) {
    if (roles == null || roles.isEmpty()) {
      throw new InvalidAccreditationException("roles are required");
    }
    Set<Role> granted;
    try {
      granted = Role.parseAll(roles.toArray(String[]::new));
    } catch (IllegalArgumentException e) {
      throw new InvalidAccreditationException("roles are unknown");
    }
    if (!ACCREDITABLE.containsAll(granted) || !granted.contains(Role.RP_CLIENT)) {
      throw new InvalidAccreditationException(
          "accreditable roles are RP_CLIENT with optional TENANT_MEMBER");
    }
    return granted;
  }

  private List<String> validateOrigins(List<String> origins) {
    if (origins == null || origins.isEmpty()) {
      throw new InvalidAccreditationException("origins are required");
    }
    List<String> clean = new ArrayList<>();
    for (String origin : origins) {
      URI uri = httpsUrl(origin, "origin");
      if (uri.getPath() != null && !uri.getPath().isBlank() && !"/".equals(uri.getPath())
          || uri.getQuery() != null || uri.getFragment() != null) {
        throw new InvalidAccreditationException("origin must have no path, query, or fragment");
      }
      clean.add(normalize(uri));
    }
    return List.copyOf(clean);
  }

  private List<String> validateAudiences(List<String> audiences) {
    if (audiences == null || audiences.isEmpty()) {
      throw new InvalidAccreditationException("audiences are required");
    }
    List<String> clean = new ArrayList<>();
    for (String audience : audiences) {
      clean.add(normalize(httpsUrl(audience, "audience")));
    }
    return List.copyOf(clean);
  }

  private URI httpsUrl(String value, String field) {
    if (value == null || value.isBlank() || value.length() > 512 || value.contains("*")) {
      throw new InvalidAccreditationException(field + " must be an exact https URL");
    }
    URI uri;
    try {
      uri = URI.create(value.strip());
    } catch (IllegalArgumentException e) {
      throw new InvalidAccreditationException(field + " must be an exact https URL");
    }
    if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
        || uri.getHost().isBlank() || uri.getUserInfo() != null) {
      throw new InvalidAccreditationException(field + " must be an exact https URL");
    }
    return uri;
  }

  private String normalize(URI uri) {
    StringBuilder normalized = new StringBuilder("https://").append(uri.getHost().toLowerCase());
    if (uri.getPort() != -1 && uri.getPort() != 443) {
      normalized.append(':').append(uri.getPort());
    }
    if (uri.getPath() != null && !uri.getPath().isBlank() && !"/".equals(uri.getPath())) {
      normalized.append(uri.getPath());
    }
    return normalized.toString();
  }

  private String slug(String orgName) {
    String slug = orgName.strip().toLowerCase().replaceAll("[^a-z0-9]+", "-");
    slug = slug.replaceAll("^-+|-+$", "");
    return slug.isEmpty() ? "org" : slug.substring(0, Math.min(slug.length(), 32));
  }

  private AccreditationView load(UUID tenantId, UUID id) {
    List<AccreditationView> rows =
        tenant.query(
            "SELECT id, org_name, roles, origins, audiences, state, requested_by, decided_by,"
                + " decided_at, credential_id, created_at FROM accreditation"
                + " WHERE tenant_id = ? AND id = ?",
            (rs, n) -> mapRow(rs),
            tenantId, id);
    if (rows.isEmpty()) {
      throw new AccreditationNotFoundException();
    }
    return rows.get(0);
  }

  private AccreditationView mapRow(java.sql.ResultSet rs) throws java.sql.SQLException {
    java.sql.Array rolesArray = rs.getArray("roles");
    java.sql.Array originsArray = rs.getArray("origins");
    java.sql.Array audiencesArray = rs.getArray("audiences");
    java.sql.Timestamp decided = rs.getTimestamp("decided_at");
    return new AccreditationView(
        rs.getObject("id", UUID.class),
        rs.getString("org_name"),
        rolesArray == null ? Set.of() : Set.of((String[]) rolesArray.getArray()),
        originsArray == null ? List.of() : List.of((String[]) originsArray.getArray()),
        audiencesArray == null ? List.of() : List.of((String[]) audiencesArray.getArray()),
        rs.getString("state"),
        rs.getString("requested_by"),
        rs.getString("decided_by"),
        decided == null ? null : decided.toInstant(),
        rs.getObject("credential_id", UUID.class),
        rs.getTimestamp("created_at").toInstant());
  }
}
