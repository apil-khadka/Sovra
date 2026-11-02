package dev.sovra.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.consent.ConsentFixtures;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Accredited RP onboarding (PROD-015): reviewed request with exact
 * roles/origins/audiences, trust-admin approval minting a bound
 * expiring credential, audience enforcement on consent creation,
 * and revocation killing the bearer. Rejections and unknown ids
 * fail with their own codes.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AccreditationFlowTests extends SovraAppRoleBase {

  static final String ORIGIN = "https://shop.example";
  static final String AUDIENCE = "https://shop.example/rp/callback";

  @LocalServerPort int port;

  @Autowired TrustService trust;

  @Autowired ObjectMapper mapper;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() throws Exception {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
    IssuanceFixtures.ensureSyntheticIssuer(owner, trust, mapper);
  }

  @Test
  void accreditedCredentialServesOnlyItsAudience() throws Exception {
    TestAccount member =
        TestAccounts.create(owner, "acc-member", Set.of("TENANT_MEMBER"));
    TestAccount admin = TestAccounts.createInTenant(
        owner, member.tenantId(), "acc-admin", Set.of("TRUST_ADMIN"));
    TestAccount issuer = TestAccounts.createInTenant(
        owner, member.tenantId(), "acc-issuer", Set.of("ISSUER_OPS"));

    Map<String, Object> requested = post("/api/accreditations", member.headers(), Map.of(
        "orgName", "Example Shop",
        "roles", List.of("RP_CLIENT"),
        "origins", List.of(ORIGIN),
        "audiences", List.of(AUDIENCE)));
    assertThat(requested.get("state")).isEqualTo("REQUESTED");
    String accreditationId = requested.get("accreditationId").toString();

    Map<String, Object> approved = post(
        "/api/accreditations/" + accreditationId + "/approve", admin.headers(), Map.of());
    assertThat(approved.get("state")).isEqualTo("APPROVED");
    String token = approved.get("oneTimeToken").toString();
    assertThat(token).isNotBlank();
    assertThat(approved.get("credentialId")).isNotNull();
    // The token appears exactly once: the read never repeats it.
    Map<String, Object> reread =
        get("/api/accreditations/" + accreditationId, admin.headers());
    assertThat(reread).doesNotContainKey("oneTimeToken");

    // The minted credential requests proofs for its own audience...
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String credentialId = ConsentFixtures.issueCredential(client, issuer, holder, mapper);
    Consumer<HttpHeaders> bearer = headers -> headers.setBearerAuth(token);
    Map<String, Object> created = post(
        "/api/consent/requests", bearer, accreditedBody(UUID.fromString(credentialId)));
    assertThat(created.get("requestId")).isNotNull();
    // ...and is refused anywhere else.
    Map<String, Object> foreign = accreditedBody(UUID.fromString(credentialId));
    foreign.put("audience", "https://evil.example/callback");
    assertThatThrownBy(() -> post("/api/consent/requests", bearer, foreign))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);

    // Revocation kills the bearer at once.
    post("/api/accreditations/" + accreditationId + "/revoke", admin.headers(), Map.of());
    assertThatThrownBy(() -> post(
            "/api/consent/requests", bearer, accreditedBody(UUID.fromString(credentialId))))
        .satisfies(e -> assertThat(((HttpClientErrorException) e).getStatusCode())
            .isIn(HttpStatusCode.valueOf(401), HttpStatusCode.valueOf(403)));
  }

  @Test
  void rejectionAndDoubleDecisionsConflict() {
    TestAccount member = TestAccounts.create(owner, "acc-rej", Set.of("TENANT_MEMBER"));
    TestAccount admin = TestAccounts.createInTenant(
        owner, member.tenantId(), "acc-rej-admin", Set.of("TRUST_ADMIN"));
    Map<String, Object> requested = post("/api/accreditations", member.headers(), Map.of(
        "orgName", "Denied Org",
        "roles", List.of("RP_CLIENT"),
        "origins", List.of(ORIGIN),
        "audiences", List.of(AUDIENCE)));
    String accreditationId = requested.get("accreditationId").toString();
    Map<String, Object> rejected =
        post("/api/accreditations/" + accreditationId + "/reject", admin.headers(), Map.of());
    assertThat(rejected.get("state")).isEqualTo("REJECTED");
    assertThatThrownBy(() -> post(
            "/api/accreditations/" + accreditationId + "/approve", admin.headers(), Map.of()))
        .isInstanceOf(HttpClientErrorException.Conflict.class);
    assertThatThrownBy(() -> post(
            "/api/accreditations/" + accreditationId + "/revoke", admin.headers(), Map.of()))
        .isInstanceOf(HttpClientErrorException.Conflict.class);
  }

  @Test
  void contractValidationRejectsLooseBindings() {
    TestAccount member = TestAccounts.create(owner, "acc-loose", Set.of("TENANT_MEMBER"));
    // Wildcard, plain http, and pathed origins are not exact.
    for (String origin : List.of(
        "https://*.example", "http://shop.example", "https://shop.example/app")) {
      assertThatThrownBy(() -> post("/api/accreditations", member.headers(), Map.of(
              "orgName", "Loose Org",
              "roles", List.of("RP_CLIENT"),
              "origins", List.of(origin),
              "audiences", List.of(AUDIENCE))))
          .isInstanceOf(HttpClientErrorException.BadRequest.class);
    }
    // Empty audiences, operator roles, and unknown roles likewise.
    assertThatThrownBy(() -> post("/api/accreditations", member.headers(), Map.of(
            "orgName", "Loose Org",
            "roles", List.of("RP_CLIENT"),
            "origins", List.of(ORIGIN),
            "audiences", List.of())))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    assertThatThrownBy(() -> post("/api/accreditations", member.headers(), Map.of(
            "orgName", "Loose Org",
            "roles", List.of("ISSUER_OPS"),
            "origins", List.of(ORIGIN),
            "audiences", List.of(AUDIENCE))))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    assertThatThrownBy(() -> post("/api/accreditations", member.headers(), Map.of(
            "orgName", "Loose Org",
            "roles", List.of("SUPERUSER"),
            "origins", List.of(ORIGIN),
            "audiences", List.of(AUDIENCE))))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void rolesGateRequestAndDecision() {
    TestAccount rp = TestAccounts.create(owner, "acc-rp", Set.of("RP_CLIENT"));
    TestAccount ops = TestAccounts.createInTenant(
        owner, rp.tenantId(), "acc-ops", Set.of("ISSUER_OPS"));
    TestAccount admin = TestAccounts.createInTenant(
        owner, rp.tenantId(), "acc-gate-admin", Set.of("TRUST_ADMIN"));
    // Bearer RP credentials cannot accredit themselves.
    assertThatThrownBy(() -> post("/api/accreditations", rp.headers(), Map.of(
            "orgName", "Self Server",
            "roles", List.of("RP_CLIENT"),
            "origins", List.of(ORIGIN),
            "audiences", List.of(AUDIENCE))))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    // Operators request but never decide.
    Map<String, Object> requested = post("/api/accreditations", ops.headers(), Map.of(
        "orgName", "Ops Org",
        "roles", List.of("RP_CLIENT"),
        "origins", List.of(ORIGIN),
        "audiences", List.of(AUDIENCE)));
    String accreditationId = requested.get("accreditationId").toString();
    assertThatThrownBy(() -> post(
            "/api/accreditations/" + accreditationId + "/approve", ops.headers(), Map.of()))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    Map<String, Object> approved = post(
        "/api/accreditations/" + accreditationId + "/approve", admin.headers(), Map.of());
    assertThat(approved.get("state")).isEqualTo("APPROVED");
  }

  @Test
  void unknownAccreditationIsNotFound() {
    TestAccount admin = TestAccounts.create(owner, "acc-missing", Set.of("TRUST_ADMIN"));
    assertThatThrownBy(
            () -> get("/api/accreditations/" + UUID.randomUUID(), admin.headers()))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
  }

  private Map<String, Object> accreditedBody(UUID credentialId) {
    Map<String, Object> body = ConsentFixtures.createBody(credentialId);
    body.put("rpId", ORIGIN + "/shop");
    body.put("audience", AUDIENCE);
    return body;
  }

  private Map<String, Object> get(String uri, Consumer<HttpHeaders> headers) {
    return client.get().uri(uri).headers(headers).retrieve().body(Map.class);
  }

  private Map<String, Object> post(
      String uri, Consumer<HttpHeaders> headers, Map<String, Object> body) {
    return client.post().uri(uri).headers(headers).body(body).retrieve().body(Map.class);
  }
}
