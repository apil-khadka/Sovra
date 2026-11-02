package dev.sovra.bff;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Privileged step-up for accreditation approval (PROD-015). The
 * interactive approve demands a hardware-bound method and a fresh
 * authentication: stale sessions and weak methods get {@code
 * step_up_required} instead of minting production credentials.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
    properties = {
      "server.port=18084",
      "sovra.bff.enabled=true",
      "sovra.bff.require-https-issuer=false",
      "sovra.bff.redirect-uri=http://localhost:18084/login/oauth2/code/sovra",
      "sovra.bff.post-logout-redirect-uri=http://localhost:18084/",
      "spring.security.oauth2.client.registration.sovra.client-id=sovra-bff",
      "spring.security.oauth2.client.registration.sovra.client-secret=stub-secret",
      "spring.security.oauth2.client.registration.sovra.scope=openid,profile,groups,tenant",
      "spring.security.oauth2.client.registration.sovra.redirect-uri=http://localhost:18084/login/oauth2/code/sovra"
    })
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class BffAccreditationStepUpTests extends SovraAppRoleBase {

  static final String BASE = "http://localhost:18084";

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

  @Autowired ObjectMapper mapper;

  JdbcTemplate owner;
  HttpClient http;
  RestClient client;

  @BeforeEach
  void setup() {
    owner = new JdbcTemplate(ownerDataSource());
    owner.update(
        "INSERT INTO tenant (slug, display_name) VALUES ('sovra-demo', 'BFF demo')"
            + " ON CONFLICT (slug) DO NOTHING");
    http = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NEVER)
        .connectTimeout(Duration.ofSeconds(10))
        .build();
    client = RestClient.builder().baseUrl(BASE).build();
  }

  @Test
  void freshHardwareSessionApproves() throws Exception {
    String accreditationId = requestedAccreditation();
    BffTestSessions.Session session = login(List.of("sovra-trust-admins"), List.of("webauthn"));
    HttpResponse<String> approved =
        postJson("/api/bff/accreditations/" + accreditationId + "/approve", session, Map.of());
    assertThat(approved.statusCode()).isEqualTo(200);
    assertThat(approved.body()).contains("APPROVED").contains("oneTimeToken");
  }

  @Test
  void staleSessionMustStepUp() throws Exception {
    String accreditationId = requestedAccreditation();
    BffTestSessions.Session session = login(List.of("sovra-trust-admins"), List.of("webauthn"));
    // Age the authentication past the step-up window, in place.
    backdateAuthTime(session.jsessionid(), Instant.now().minus(Duration.ofMinutes(16)));
    HttpResponse<String> refused =
        postJson("/api/bff/accreditations/" + accreditationId + "/approve", session, Map.of());
    assertThat(refused.statusCode()).isEqualTo(401);
    assertThat(refused.body()).contains("step_up_required");
    // Nothing minted: the accreditation is still undecided.
    assertThat(state(accreditationId)).isEqualTo("REQUESTED");
  }

  @Test
  void weakMethodMustStepUp() throws Exception {
    // Login itself refuses weak methods for privileged groups, so
    // the endpoint's own check is exercised by downgrading the
    // session's method record in place.
    String accreditationId = requestedAccreditation();
    BffTestSessions.Session session = login(List.of("sovra-trust-admins"), List.of("webauthn"));
    int downgraded = owner.update(
        "UPDATE spring_session_attributes SET attribute_bytes = ? WHERE session_primary_id ="
            + " (SELECT primary_id FROM spring_session WHERE session_id = ?)"
            + " AND attribute_name = ?",
        "{\"t\":\"sl\",\"v\":[\"pwd\"]}".getBytes(StandardCharsets.UTF_8),
        session.jsessionid(), "sovra.amr");
    assertThat(downgraded).isEqualTo(1);
    HttpResponse<String> refused =
        postJson("/api/bff/accreditations/" + accreditationId + "/approve", session, Map.of());
    assertThat(refused.statusCode()).isEqualTo(401);
    assertThat(refused.body()).contains("step_up_required");
    assertThat(state(accreditationId)).isEqualTo("REQUESTED");
  }

  private String requestedAccreditation() {
    // The requester lives in the BFF demo tenant, so the BFF
    // approver decides a case it can actually see.
    UUID demo = owner.queryForObject(
        "SELECT id FROM tenant WHERE slug = 'sovra-demo'", UUID.class);
    TestAccount member = TestAccounts.createInTenant(
        owner, demo, "bff-acc-" + suffix(), Set.of("TENANT_MEMBER"));
    Map<String, Object> requested = client.post().uri("/api/accreditations")
        .headers(member.headers())
        .body(Map.of(
            "orgName", "Step-Up Shop",
            "roles", List.of("RP_CLIENT"),
            "origins", List.of("https://shop.example"),
            "audiences", List.of("https://shop.example/rp/callback")))
        .retrieve()
        .body(Map.class);
    return requested.get("accreditationId").toString();
  }

  private BffTestSessions.Session login(List<String> groups, List<String> amr) throws Exception {
    return BffTestSessions.login(
        http, mapper, BASE, STUB,
        new StubOpenIdProvider.Script(
            "stepup-" + suffix(), groups, "sovra-demo", amr));
  }

  private void backdateAuthTime(String jsessionid, Instant at) throws Exception {
    List<Map<String, Object>> rows = owner.queryForList(
        "SELECT a.attribute_name, a.attribute_bytes FROM spring_session_attributes a"
            + " JOIN spring_session s ON s.primary_id = a.session_primary_id"
            + " WHERE s.session_id = ?",
        jsessionid);
    assertThat(rows).isNotEmpty();
    String envelope =
        "{\"t\":\"s\",\"v\":\"" + at.toString() + "\"}";
    int updated = owner.update(
        "UPDATE spring_session_attributes SET attribute_bytes = ? WHERE session_primary_id ="
            + " (SELECT primary_id FROM spring_session WHERE session_id = ?)"
            + " AND attribute_name = ?",
        envelope.getBytes(StandardCharsets.UTF_8), jsessionid, "sovra.authTime");
    assertThat(updated).isEqualTo(1);
  }

  private String state(String accreditationId) {
    return owner.queryForObject(
        "SELECT state FROM accreditation WHERE id = ?", String.class,
        UUID.fromString(accreditationId));
  }

  private HttpResponse<String> postJson(
      String path, BffTestSessions.Session session, Map<String, Object> body) throws Exception {
    HttpRequest request = HttpRequest.newBuilder(URI.create(BASE + path))
        .timeout(Duration.ofSeconds(30))
        .header(
            "Cookie", "JSESSIONID=" + session.jsessionid() + "; XSRF-TOKEN=" + session.xsrf())
        .header("X-XSRF-TOKEN", session.xsrf())
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
        .build();
    return http.send(request, HttpResponse.BodyHandlers.ofString());
  }

  private static String suffix() {
    return UUID.randomUUID().toString().substring(0, 8);
  }
}
