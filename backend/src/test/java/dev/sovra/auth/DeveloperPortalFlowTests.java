package dev.sovra.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.consent.ConsentFixtures;
import dev.sovra.verification.VerificationFixtures;
import dev.sovra.verification.VerificationFixtures.Stage;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Developer portal and RP dashboard over the machine chain
 * (SOV-022/SOV-025): public discovery, member-minted
 * fixed-shape sandbox credentials, RP-subset rotation, and
 * audience-scoped outcomes and metrics. The BFF session twin
 * is covered in {@code BffIssuerFlowTests}; the services
 * underneath are shared.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class DeveloperPortalFlowTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  @Autowired ObjectMapper mapper;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> get(String path, TestAccount caller) {
    var request = client.get().uri(path);
    if (caller != null) {
      request.headers(caller.headers());
    }
    return request.retrieve().body(Map.class);
  }

  @SuppressWarnings("unchecked")
  private List<Map<String, Object>> getList(String path, TestAccount caller) {
    var request = client.get().uri(path);
    if (caller != null) {
      request.headers(caller.headers());
    }
    return request.retrieve().body(List.class);
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> post(String path, TestAccount caller, Map<String, Object> body) {
    return client
        .post()
        .uri(path)
        .headers(caller.headers())
        .contentType(MediaType.APPLICATION_JSON)
        .body(body)
        .retrieve()
        .body(Map.class);
  }

  @Test
  @SuppressWarnings("unchecked")
  void discoveryIsPublicAndStatic() {
    Map<String, Object> discovery = get("/api/discovery", null);
    assertThat(discovery).isNotNull();
    assertThat(discovery.get("service")).isEqualTo("sovra-backend");
    assertThat(discovery.get("contractVersion")).isEqualTo("0.16.0");
    assertThat(discovery.get("profile")).isEqualTo("synthetic");
    Map<String, Object> sandbox = (Map<String, Object>) discovery.get("sandbox");
    assertThat(sandbox.get("namePattern")).isEqualTo("sandbox-<app>");
    assertThat(sandbox.get("roles")).isEqualTo(List.of("RP_CLIENT"));
    assertThat(sandbox.get("ttlHours")).isEqualTo(24);
    Map<String, Object> sdks = (Map<String, Object>) discovery.get("sdks");
    assertThat(sdks.get("java")).isEqualTo("0.16.0");
    assertThat(sdks.get("typescript")).isEqualTo("0.16.0");
  }

  @Test
  void memberOnboardsFixedShapeSandboxAccount() {
    TestAccount member = TestAccounts.create(owner, "portal-member", Set.of("TENANT_MEMBER"));

    Map<String, Object> created =
        post("/api/sandbox/accounts", member, Map.of("name", "sandbox-my-app"));
    assertThat(created).isNotNull();
    assertThat(created.get("name")).isEqualTo("sandbox-my-app");
    assertThat(created.get("roles")).isEqualTo(List.of("RP_CLIENT"));
    assertThat(created.get("token").toString()).isNotBlank();
    Instant expiresAt = Instant.parse(created.get("expiresAt").toString());
    assertThat(expiresAt).isAfter(Instant.now().plusSeconds(23 * 3600));
    assertThat(expiresAt).isBefore(Instant.now().plusSeconds(25 * 3600));

    // The minted sandbox token is a working RP credential.
    TestAccount sandbox = new TestAccount(member.tenantId(), member.tenantSlug(),
        java.util.UUID.fromString(created.get("id").toString()), "sandbox-my-app",
        created.get("token").toString(), Set.of(dev.sovra.authz.Role.RP_CLIENT));
    Map<String, Object> metrics = get("/api/rp/metrics", sandbox);
    assertThat(metrics).isNotNull();
    assertThat(((Number) metrics.get("total")).longValue()).isEqualTo(0);

    // Token material never reads back; the list shows metadata only.
    List<Map<String, Object>> listed = getList("/api/sandbox/accounts", member);
    assertThat(listed).hasSize(1);
    assertThat(listed.get(0).get("name")).isEqualTo("sandbox-my-app");
    assertThat(listed.get(0)).doesNotContainKey("token");
    assertThat(listed.get(0).get("roles")).isEqualTo(List.of("RP_CLIENT"));
  }

  @Test
  void sandboxNamesAreConstrained() {
    TestAccount member = TestAccounts.create(owner, "portal-namer", Set.of("TENANT_MEMBER"));
    for (String bad : List.of("prod-key", "sandbox-", "sandbox-a!", "x", "sandbox- ok")) {
      assertThatThrownBy(() -> post("/api/sandbox/accounts", member, Map.of("name", bad)))
          .isInstanceOf(HttpClientErrorException.BadRequest.class);
    }
    Map<String, Object> created =
        post("/api/sandbox/accounts", member, Map.of("name", "sandbox-ok-1"));
    assertThat(created.get("name")).isEqualTo("sandbox-ok-1");
  }

  @Test
  void relyingPartyCannotMintSandbox() {
    TestAccount rp = TestAccounts.create(owner, "portal-rp", Set.of("RP_CLIENT"));
    assertThatThrownBy(() -> post("/api/sandbox/accounts", rp, Map.of("name", "sandbox-nope")))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
  }

  @Test
  void memberRotatesAndRevokesRpCredential() {
    TestAccount member = TestAccounts.create(owner, "portal-rotator", Set.of("TENANT_MEMBER"));
    Map<String, Object> created =
        post("/api/sandbox/accounts", member, Map.of("name", "sandbox-spin"));
    String id = created.get("id").toString();
    String first = created.get("token").toString();

    Map<String, Object> rotated =
        post("/api/rp/credentials/" + id + "/rotate", member, Map.of());
    String second = rotated.get("token").toString();
    assertThat(second).isNotBlank().isNotEqualTo(first);

    TestAccount stale = sandboxAccount(member, id, first);
    TestAccount fresh = sandboxAccount(member, id, second);
    assertThatThrownBy(() -> get("/api/rp/metrics", stale))
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
    assertThat(get("/api/rp/metrics", fresh)).isNotNull();

    Map<String, Object> revoked = post("/api/rp/credentials/" + id + "/revoke", member, Map.of());
    assertThat(revoked.get("revoked")).isEqualTo(Boolean.TRUE);
    assertThatThrownBy(() -> get("/api/rp/metrics", fresh))
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
  }

  @Test
  void relyingPartyCannotTouchSiblingCredentials() {
    TestAccount member = TestAccounts.create(owner, "portal-owner", Set.of("TENANT_MEMBER"));
    TestAccount rp = TestAccounts.createInTenant(
        owner, member.tenantId(), "portal-sibling", Set.of("RP_CLIENT"));
    Map<String, Object> created =
        post("/api/sandbox/accounts", member, Map.of("name", "sandbox-victim"));
    String id = created.get("id").toString();

    assertThatThrownBy(() -> get("/api/rp/apps", rp))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(() -> post("/api/rp/credentials/" + id + "/rotate", rp, Map.of()))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(() -> post("/api/rp/credentials/" + id + "/revoke", rp, Map.of()))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
  }

  @Test
  void trustAndIssuerAccountsInvisibleToRpDesk() {
    TestAccount admin = TestAccounts.create(owner, "portal-admin", Set.of("TRUST_ADMIN"));
    TestAccount issuer = TestAccounts.createInTenant(
        owner, admin.tenantId(), "portal-issuer", Set.of("ISSUER_OPS"));
    TestAccount member = TestAccounts.createInTenant(
        owner, admin.tenantId(), "portal-member2", Set.of("TENANT_MEMBER"));
    Map<String, Object> created =
        post("/api/sandbox/accounts", member, Map.of("name", "sandbox-visible"));

    List<Map<String, Object>> apps = getList("/api/rp/apps", member);
    assertThat(apps.stream().map(app -> app.get("name")).toList())
        .containsExactly("sandbox-visible");

    // Out-of-subset accounts 404 like unknown ones: no existence oracle.
    assertThatThrownBy(
            () -> post("/api/rp/credentials/" + admin.accountId() + "/rotate", member, Map.of()))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
    assertThatThrownBy(
            () -> post("/api/rp/credentials/" + issuer.accountId() + "/revoke", member, Map.of()))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
    assertThat(created.get("name")).isEqualTo("sandbox-visible");
  }

  @Test
  @SuppressWarnings("unchecked")
  void rpOutcomesAreAudienceScoped() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "portal-outcome");
    String nonce = VerificationFixtures.nonce();
    Map<String, Object> decided = VerificationFixtures.verify(client, stage.rp(),
        VerificationFixtures.verifyBody(
            stage.holder(), stage.requestId(), nonce, ConsentFixtures.AUDIENCE, mapper));
    assertThat(decided.get("outcome")).isEqualTo("ACCEPTED");
    String decisionId = decided.get("decisionId").toString();
    TestAccount sibling = TestAccounts.createInTenant(
        owner, stage.rp().tenantId(), "portal-sib", Set.of("RP_CLIENT"));

    List<Map<String, Object>> own = getList("/api/rp/outcomes", stage.rp());
    assertThat(own).hasSize(1);
    Map<String, Object> row = own.get(0);
    assertThat(row.get("decisionId")).isEqualTo(decisionId);
    assertThat(row.get("requestId")).isEqualTo(stage.requestId());
    assertThat(row.get("rpId")).isEqualTo(ConsentFixtures.RP_ID);
    assertThat(row.get("outcome")).isEqualTo("ACCEPTED");
    assertThat(row.keySet())
        .containsExactlyInAnyOrder(
            "decisionId", "requestId", "rpId", "outcome", "reasonCode", "decidedAt");

    // A sibling relying party sees none of it; the tenant agent sees all.
    assertThat(getList("/api/rp/outcomes", sibling)).isEmpty();
    assertThat(getList("/api/rp/outcomes", stage.holderAgent())).hasSize(1);
  }

  @Test
  void rpMetricsCountOwnDecisions() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "portal-metrics");
    String nonce = VerificationFixtures.nonce();
    VerificationFixtures.verify(client, stage.rp(), VerificationFixtures.verifyBody(
        stage.holder(), stage.requestId(), nonce, ConsentFixtures.AUDIENCE, mapper));
    TestAccount sibling = TestAccounts.createInTenant(
        owner, stage.rp().tenantId(), "portal-sib2", Set.of("RP_CLIENT"));

    Map<String, Object> own = get("/api/rp/metrics", stage.rp());
    assertThat(((Number) own.get("total")).longValue()).isEqualTo(1);
    assertThat(((Number) own.get("accepted")).longValue()).isEqualTo(1);
    assertThat(((Number) own.get("rejected")).longValue()).isEqualTo(0);
    assertThat(((Number) get("/api/rp/metrics", sibling).get("total")).longValue()).isEqualTo(0);
    assertThat(((Number) get("/api/rp/metrics", stage.holderAgent()).get("total")).longValue())
        .isEqualTo(1);
  }

  private TestAccount sandboxAccount(TestAccount member, String id, String token) {
    return new TestAccount(member.tenantId(), member.tenantSlug(),
        java.util.UUID.fromString(id), "sandbox-spin", token,
        Set.of(dev.sovra.authz.Role.RP_CLIENT));
  }
}
