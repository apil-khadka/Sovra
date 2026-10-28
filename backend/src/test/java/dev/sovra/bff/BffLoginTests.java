package dev.sovra.bff;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.auth.HumanMembershipRepository;
import dev.sovra.auth.HumanMembershipRepository.MembershipRow;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ResourceRef;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * BFF login over a scripted OpenID Provider (SOV-006): auth code
 * with forced S256 PKCE, exact issuer/audience matching, tenant
 * allowlisting, group-to-role mapping, hardware-AMR gating for
 * privileged roles, session/mid-session revocation, chain separation,
 * and CSRF-protected logout. The stub OP genuinely verifies the PKCE
 * verifier on every login, so the suite proves the code is bound to
 * the browser session end to end.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
    properties = {
      "server.port=18082",
      "sovra.bff.enabled=true",
      "sovra.bff.require-https-issuer=false",
      "sovra.bff.redirect-uri=http://localhost:18082/login/oauth2/code/sovra",
      "sovra.bff.post-logout-redirect-uri=http://localhost:18082/",
      "spring.security.oauth2.client.registration.sovra.client-id=sovra-bff",
      "spring.security.oauth2.client.registration.sovra.client-secret=stub-secret",
      "spring.security.oauth2.client.registration.sovra.scope=openid,profile,groups,tenant",
      "spring.security.oauth2.client.registration.sovra.redirect-uri=http://localhost:18082/login/oauth2/code/sovra"
    })
class BffLoginTests extends SovraAppRoleBase {

  static final StubOpenIdProvider STUB;

  static {
    try {
      STUB = new StubOpenIdProvider("sovra-bff", "stub-secret");
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  @DynamicPropertySource
  static void stubProvider(DynamicPropertyRegistry registry) {
    registry.add(
        "spring.security.oauth2.client.provider.sovra.issuer-uri", STUB::issuer);
    registry.add("sovra.bff.issuer", STUB::issuer);
    registry.add("sovra.bff.end-session-endpoint", () -> STUB.baseUrl() + "/stub-logout");
  }

  @AfterAll
  static void closeStub() {
    STUB.close();
  }

  @Autowired ObjectMapper mapper;

  @Autowired HumanMembershipRepository memberships;

  @Autowired AuthorizationService authz;

  JdbcTemplate owner;
  HttpClient http;

  @BeforeEach
  void setup() {
    owner = new JdbcTemplate(ownerDataSource());
    owner.update(
        "INSERT INTO tenant (slug, display_name) VALUES ('sovra-demo', 'BFF demo')"
            + " ON CONFLICT (slug) DO NOTHING");
    http = HttpClient.newBuilder()
        .followRedirects(Redirect.NEVER)
        .connectTimeout(Duration.ofSeconds(10))
        .build();
  }

  private static final String BASE = "http://localhost:18082";

  record Session(String jsessionid, String xsrf) {}

  private HttpResponse<String> get(String url, Map<String, String> headers) throws Exception {
    return BffTestSessions.get(http, url, headers);
  }

  private static String cookie(HttpResponse<?> response, String name) {
    return BffTestSessions.cookie(response, name);
  }

  private static String location(HttpResponse<?> response) {
    return BffTestSessions.location(response);
  }

  private String dance(Map<String, String> jar) throws Exception {
    return BffTestSessions.dance(http, BASE, jar);
  }

  private Session login(StubOpenIdProvider.Script script) throws Exception {
    BffTestSessions.Session shared = BffTestSessions.login(http, mapper, BASE, STUB, script);
    return new Session(shared.jsessionid(), shared.xsrf());
  }

  private JsonNode me(Session session) throws Exception {
    return BffTestSessions.me(http, mapper, BASE,
        new BffTestSessions.Session(session.jsessionid(), session.xsrf()));
  }

  private UUID demoTenant() {
    return owner.queryForObject(
        "SELECT id FROM tenant WHERE slug = 'sovra-demo'", UUID.class);
  }

  @Test
  void loginHappyPathProvisionsMembershipAndAudits() throws Exception {
    String subject = "member-" + UUID.randomUUID().toString().substring(0, 8);
    Session session = login(new StubOpenIdProvider.Script(
        subject, List.of("sovra-members"), "sovra-demo", List.of("pwd")));
    JsonNode identity = me(session);
    assertThat(identity.get("displayName").asString()).isEqualTo(subject);
    assertThat(identity.get("tenantId").asString()).isEqualTo(demoTenant().toString());
    assertThat(identity.get("roles").toString()).contains("TENANT_MEMBER");
    assertThat(session.xsrf()).isNotNull();

    MembershipRow stored =
        memberships.findBySubject(STUB.issuer(), subject).orElseThrow();
    assertThat(stored.tenantId()).isEqualTo(demoTenant());
    assertThat(stored.roles()).isEqualTo(Set.of("TENANT_MEMBER"));

    Map<String, Object> audit = TestAccounts.auditRow(owner, "BFF_LOGIN");
    assertThat(audit.get("decision")).isEqualTo("PERMIT");
    assertThat(audit.get("actor_id").toString()).isEqualTo(stored.id().toString());
    assertThat(audit.get("detail").toString()).contains(subject);
  }

  @Test
  void privilegedRoleNeedsHardwareAmr() throws Exception {
    String subject = "priv-" + UUID.randomUUID().toString().substring(0, 8);
    Session session = login(new StubOpenIdProvider.Script(
        subject, List.of("sovra-members", "sovra-trust-admins"), "sovra-demo", List.of("webauthn")));
    assertThat(me(session).get("roles").toString()).contains("TRUST_ADMIN");

    // Same groups without the hardware method: privileged roles are
    // withheld, the login still succeeds with the remainder.
    String partial = "part-" + UUID.randomUUID().toString().substring(0, 8);
    Session reduced = login(new StubOpenIdProvider.Script(
        partial, List.of("sovra-members", "sovra-trust-admins"), "sovra-demo", List.of("pwd")));
    JsonNode identity = me(reduced);
    assertThat(identity.get("roles").toString()).contains("TENANT_MEMBER");
    assertThat(identity.get("roles").toString()).doesNotContain("TRUST_ADMIN");

    // Privileged-only without hardware: the login itself is denied.
    String denied = "deny-" + UUID.randomUUID().toString().substring(0, 8);
    STUB.script(new StubOpenIdProvider.Script(
        denied, List.of("sovra-trust-admins"), "sovra-demo", List.of("pwd")));
    Map<String, String> jar = new java.util.HashMap<>();
    assertThat(dance(jar)).isEqualTo(BASE + "/?auth_error=ASSURANCE_INSUFFICIENT");
    assertThat(memberships.findBySubject(STUB.issuer(), denied)).isEmpty();
  }

  @Test
  void wrongIssuerAndAudienceNeverReachLogin() throws Exception {
    STUB.script(new StubOpenIdProvider.Script(
        "evil", List.of("sovra-members"), "sovra-demo", List.of("pwd"),
        "https://evil.example/realms/sovra", null));
    Map<String, String> jar = new java.util.HashMap<>();
    assertThat(dance(jar)).isEqualTo(BASE + "/?auth_error=UNTRUSTED_ISSUER");

    STUB.script(new StubOpenIdProvider.Script(
        "evil-aud", List.of("sovra-members"), "sovra-demo", List.of("pwd"), null, "someone-else"));
    Map<String, String> jar2 = new java.util.HashMap<>();
    assertThat(dance(jar2)).isEqualTo(BASE + "/?auth_error=UNTRUSTED_ISSUER");
  }

  @Test
  void unknownTenantAndUnmappedGroupsDenied() throws Exception {
    STUB.script(new StubOpenIdProvider.Script(
        "no-tenant", List.of("sovra-members"), "other-tenant", List.of("pwd")));
    Map<String, String> jar = new java.util.HashMap<>();
    assertThat(dance(jar)).isEqualTo(BASE + "/?auth_error=WRONG_TENANT");

    String nobody = "nobody-" + UUID.randomUUID().toString().substring(0, 8);
    STUB.script(new StubOpenIdProvider.Script(
        nobody, List.of("strangers"), "sovra-demo", List.of("pwd")));
    Map<String, String> jar2 = new java.util.HashMap<>();
    assertThat(dance(jar2)).isEqualTo(BASE + "/?auth_error=MISSING_ROLE");
    // Tenant-resolved denials are audit rows, not silent drops.
    Map<String, Object> audit = TestAccounts.auditRow(owner, "BFF_LOGIN");
    assertThat(audit.get("decision")).isEqualTo("DENY");
    assertThat(audit.get("reason_code")).isEqualTo("MISSING_ROLE");
    assertThat(audit.get("detail").toString()).contains(nobody);
  }

  @Test
  void revocationDeniesNextLoginAndKillsLiveSession() throws Exception {
    String subject = "rev-" + UUID.randomUUID().toString().substring(0, 8);
    Session session = login(new StubOpenIdProvider.Script(
        subject, List.of("sovra-members"), "sovra-demo", List.of("pwd")));
    MembershipRow stored = memberships.findBySubject(STUB.issuer(), subject).orElseThrow();
    memberships.revoke(stored.id());

    // The live session dies on the next request.
    HttpResponse<String> after = get(BASE + "/api/bff/me",
        Map.of("Cookie", "JSESSIONID=" + session.jsessionid()));
    assertThat(after.statusCode()).isEqualTo(401);

    // And the next login is denied without re-provisioning.
    STUB.script(new StubOpenIdProvider.Script(
        subject, List.of("sovra-members"), "sovra-demo", List.of("pwd")));
    Map<String, String> jar = new java.util.HashMap<>();
    assertThat(dance(jar)).isEqualTo(BASE + "/?auth_error=CREDENTIAL_REVOKED");
    assertThat(memberships.findBySubject(STUB.issuer(), subject).orElseThrow().revoked()).isTrue();
  }

  @Test
  void roleRemovalInvalidatesWarmGrants() throws Exception {
    String subject = "downgrade-" + UUID.randomUUID().toString().substring(0, 8);
    login(new StubOpenIdProvider.Script(
        subject, List.of("sovra-members", "sovra-rp"), "sovra-demo", List.of("pwd")));
    MembershipRow stored = memberships.findBySubject(STUB.issuer(), subject).orElseThrow();
    ServiceAccountPrincipal principal = stored.principal();
    ResourceRef resource = ResourceRef.tenantScoped("proof", "downgrade-probe", demoTenant());

    Decision before = authz.authorize(Optional.of(principal), Action.REQUEST_PROOF, resource);
    assertThat(before.permitted()).isTrue();

    // Re-login with fewer groups: the sync path rewrites the row and
    // evicts the principal's cached grants.
    login(new StubOpenIdProvider.Script(
        subject, List.of("sovra-members"), "sovra-demo", List.of("pwd")));
    MembershipRow narrowed = memberships.findBySubject(STUB.issuer(), subject).orElseThrow();
    assertThat(narrowed.roles()).isEqualTo(Set.of("TENANT_MEMBER"));

    Decision after =
        authz.authorize(Optional.of(narrowed.principal()), Action.REQUEST_PROOF, resource);
    assertThat(after.permitted()).isFalse();
    assertThat(after.reasonCode().name()).isEqualTo("MISSING_ROLE");
  }

  @Test
  void machineAndSessionChainsStaySeparate() throws Exception {
    String subject = "sep-" + UUID.randomUUID().toString().substring(0, 8);
    Session session = login(new StubOpenIdProvider.Script(
        subject, List.of("sovra-members"), "sovra-demo", List.of("pwd")));
    TestAccount machine = TestAccounts.create(owner, "sep-machine", Set.of("TENANT_MEMBER"));

    // Machine credentials never authenticate the BFF.
    HttpResponse<String> bff = get(BASE + "/api/bff/me",
        Map.of("Authorization", "Bearer " + machine.token()));
    assertThat(bff.statusCode()).isEqualTo(401);

    // Sessions never authenticate the machine API.
    HttpResponse<String> api = get(
        BASE + "/api/consent/requests/" + UUID.randomUUID(),
        Map.of("Cookie", "JSESSIONID=" + session.jsessionid()));
    assertThat(api.statusCode()).isEqualTo(401);

    // No session at all: anonymous on the BFF.
    assertThat(get(BASE + "/api/bff/me", Map.of()).statusCode()).isEqualTo(401);
  }

  @Test
  void trustAdminSessionManagesServiceAccounts() throws Exception {
    String subject = "ops-" + UUID.randomUUID().toString().substring(0, 8);
    Session session = login(new StubOpenIdProvider.Script(
        subject, List.of("sovra-trust-admins"), "sovra-demo", List.of("webauthn")));

    // Same service as the machine chain, over a CSRF-armed session.
    String payload = mapper.writeValueAsString(
        Map.of("name", "bff-minted", "roles", List.of("TENANT_MEMBER")));
    HttpRequest create = HttpRequest.newBuilder(
            URI.create(BASE + "/api/bff/service-accounts"))
        .timeout(Duration.ofSeconds(30))
        .header("Cookie", "JSESSIONID=" + session.jsessionid() + "; XSRF-TOKEN=" + session.xsrf())
        .header("X-XSRF-TOKEN", session.xsrf())
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(payload))
        .build();
    HttpResponse<String> created = http.send(create, HttpResponse.BodyHandlers.ofString());
    assertThat(created.statusCode()).isEqualTo(201);
    String token = mapper.readTree(created.body()).get("token").asString();

    // The minted machine token authenticates the machine chain.
    HttpResponse<String> probe = get(BASE + "/api/auth/service-accounts",
        Map.of("Authorization", "Bearer " + token));
    assertThat(probe.statusCode()).isEqualTo(403);

    // A member session is denied the admin surface on its own chain.
    String member = "ops-member-" + UUID.randomUUID().toString().substring(0, 8);
    Session reduced = login(new StubOpenIdProvider.Script(
        member, List.of("sovra-members"), "sovra-demo", List.of("pwd")));
    HttpResponse<String> denied = get(BASE + "/api/bff/service-accounts",
        Map.of("Cookie", "JSESSIONID=" + reduced.jsessionid()));
    assertThat(denied.statusCode()).isEqualTo(403);
  }

  @Test
  void logoutNeedsCsrfThenKillsSessionWithOpUrl() throws Exception {
    String subject = "logout-" + UUID.randomUUID().toString().substring(0, 8);
    Session session = login(new StubOpenIdProvider.Script(
        subject, List.of("sovra-members"), "sovra-demo", List.of("pwd")));
    assertThat(session.xsrf()).isNotNull();

    HttpRequest bare = HttpRequest.newBuilder(
            URI.create(BASE + "/api/bff/logout"))
        .timeout(Duration.ofSeconds(30))
        .header("Cookie", "JSESSIONID=" + session.jsessionid() + "; XSRF-TOKEN=" + session.xsrf())
        .POST(HttpRequest.BodyPublishers.noBody())
        .build();
    HttpResponse<String> denied = http.send(bare, HttpResponse.BodyHandlers.ofString());
    assertThat(denied.statusCode()).isEqualTo(403);

    HttpRequest armed = HttpRequest.newBuilder(
            URI.create(BASE + "/api/bff/logout"))
        .timeout(Duration.ofSeconds(30))
        .header("Cookie", "JSESSIONID=" + session.jsessionid() + "; XSRF-TOKEN=" + session.xsrf())
        .header("X-XSRF-TOKEN", session.xsrf())
        .POST(HttpRequest.BodyPublishers.noBody())
        .build();
    HttpResponse<String> done = http.send(armed, HttpResponse.BodyHandlers.ofString());
    assertThat(done.statusCode()).isEqualTo(200);
    JsonNode body = mapper.readTree(done.body());
    assertThat(body.get("loggedOut").asBoolean()).isTrue();
    assertThat(body.get("endSessionUrl").asString())
        .contains("id_token_hint=")
        .contains("post_logout_redirect_uri=" + "http%3A%2F%2Flocalhost%3A18082%2F");

    assertThat(get(BASE + "/api/bff/me",
            Map.of("Cookie", "JSESSIONID=" + session.jsessionid())).statusCode())
        .isEqualTo(401);
    assertThat(TestAccounts.auditRow(owner, "BFF_LOGOUT").get("decision")).isEqualTo("PERMIT");
  }
}
