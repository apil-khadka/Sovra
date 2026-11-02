package dev.sovra.bff;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.SovraApplication;
import dev.sovra.auth.HumanMembershipRepository;
import dev.sovra.issuance.IssuanceFixtures;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Shared BFF sessions across replicas (PROD-003, F-02). Two
 * application instances on different ports share one database: a
 * browser that logs in on replica A must work on replica B with no
 * second login, an unlock challenge issued on A must consume exactly
 * once from anywhere, and revocation or logout on one replica must
 * take effect on the other immediately. Session bytes are asserted
 * to be JSON, and the session timeout to be the configured 30
 * minutes.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
    properties = {
      "server.port=18088",
      "sovra.bff.enabled=true",
      "sovra.bff.require-https-issuer=false",
      "sovra.bff.redirect-uri=http://localhost:18088/login/oauth2/code/sovra",
      "sovra.bff.post-logout-redirect-uri=http://localhost:18088/",
      "spring.security.oauth2.client.registration.sovra.client-id=sovra-bff",
      "spring.security.oauth2.client.registration.sovra.client-secret=stub-secret",
      "spring.security.oauth2.client.registration.sovra.scope=openid,profile,groups,tenant",
      "spring.security.oauth2.client.registration.sovra.redirect-uri=http://localhost:18088/login/oauth2/code/sovra"
    })
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class BffSessionSharingTests extends SovraAppRoleBase {

  static final String BASE_A = "http://localhost:18088";
  static final String BASE_B = "http://localhost:18089";

  static final StubOpenIdProvider STUB;

  static {
    try {
      STUB = new StubOpenIdProvider("sovra-bff", "stub-secret");
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /** Second replica: same code, same database, separate memory and port. */
  static ConfigurableApplicationContext replica;

  @BeforeAll
  static void startReplica() {
    // Inlined properties beat application.yaml; the builder's own
    // properties map would lose to it as mere defaults.
    replica = new SpringApplicationBuilder(SovraApplication.class)
        .initializers(
            (org.springframework.context.ApplicationContextInitializer<
                    org.springframework.context.ConfigurableApplicationContext>)
                context ->
                    org.springframework.test.context.support.TestPropertySourceUtils
                        .addInlinedPropertiesToEnvironment(
                            context,
                            "server.port=18089",
                            "spring.datasource.url=" + containerJdbcUrl(),
                            "spring.datasource.username=" + appRoleName(),
                            "spring.datasource.password=" + appRolePassword(),
                            "spring.flyway.user=" + containerUsername(),
                            "spring.flyway.password=" + containerPassword(),
                            "sovra.bff.enabled=true",
                            "sovra.bff.require-https-issuer=false",
                            // Behind a balancer both replicas share one public
                            // origin, so both register the same callback. The
                            // cross-callback test below relies on that.
                            "sovra.bff.redirect-uri=" + BASE_A + "/login/oauth2/code/sovra",
                            "sovra.bff.post-logout-redirect-uri=" + BASE_B + "/",
                            "sovra.bff.issuer=" + STUB.issuer(),
                            "sovra.bff.end-session-endpoint=" + STUB.baseUrl() + "/stub-logout",
                            "spring.security.oauth2.client.registration.sovra.client-id=sovra-bff",
                            "spring.security.oauth2.client.registration.sovra.client-secret=stub-secret",
                            "spring.security.oauth2.client.registration.sovra.scope=openid,profile,groups,tenant",
                            "spring.security.oauth2.client.registration.sovra.redirect-uri=" + BASE_A
                                + "/login/oauth2/code/sovra",
                            "spring.security.oauth2.client.provider.sovra.issuer-uri="
                                + STUB.issuer()))
        .run();
  }

  @AfterAll
  static void stopReplica() {
    if (replica != null) {
      replica.close();
    }
    STUB.close();
  }

  @DynamicPropertySource
  static void stubProvider(DynamicPropertyRegistry registry) {
    registry.add(
        "spring.security.oauth2.client.provider.sovra.issuer-uri", STUB::issuer);
    registry.add("sovra.bff.issuer", STUB::issuer);
    registry.add("sovra.bff.end-session-endpoint", () -> STUB.baseUrl() + "/stub-logout");
  }

  @Autowired ObjectMapper mapper;

  @Autowired HumanMembershipRepository memberships;

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

  @Test
  void loginOnAWarmsBWithNoSecondLogin() throws Exception {
    String subject = "share-" + suffix();
    BffTestSessions.Session session = login(subject);
    JsonNode a = me(BASE_A, session);
    JsonNode b = me(BASE_B, session);
    assertThat(b.get("displayName").asString()).isEqualTo(a.get("displayName").asString());
    assertThat(b.get("displayName").asString()).contains(subject);

    // The session genuinely lives in the shared store: one row,
    // JSON attribute bytes, and the configured 30-minute timeout.
    String sessionId = session.jsessionid();
    Map<String, Object> row = owner.queryForMap(
        "SELECT max_inactive_interval, expiry_time, last_access_time FROM spring_session"
            + " WHERE session_id = ?",
        sessionId);
    assertThat(((Number) row.get("max_inactive_interval")).intValue()).isEqualTo(1800);
    List<byte[]> attributes = owner.query(
        "SELECT attribute_bytes FROM spring_session_attributes WHERE session_primary_id ="
            + " (SELECT primary_id FROM spring_session WHERE session_id = ?)",
        (rs, n) -> rs.getBytes("attribute_bytes"),
        sessionId);
    assertThat(attributes).isNotEmpty();
    for (byte[] bytes : attributes) {
      assertThat(new String(bytes, StandardCharsets.UTF_8)).startsWith("{\"t\":");
    }
  }

  @Test
  void callbackMayLandOnEitherReplica() throws Exception {
    // Dance starts on A; the callback is delivered to B. Behind a
    // balancer the callback host is whoever the balancer picks — the
    // authorization request and PKCE verifier come from the shared
    // store either way.
    STUB.script(new StubOpenIdProvider.Script(
        "split-" + suffix(), List.of("sovra-members"), "sovra-demo", List.of("pwd")));
    HttpResponse<String> start =
        BffTestSessions.get(http, BASE_A + "/oauth2/authorization/sovra", Map.of());
    assertThat(start.statusCode()).isEqualTo(302);
    String pre = BffTestSessions.cookie(start, "JSESSIONID");
    assertThat(pre).isNotNull();
    HttpResponse<String> approved =
        BffTestSessions.get(http, BffTestSessions.location(start), Map.of());
    assertThat(approved.statusCode()).isEqualTo(302);
    String callbackOnB = BffTestSessions.location(approved).replace(BASE_A, BASE_B);
    HttpResponse<String> landing = BffTestSessions.get(
        http, callbackOnB, Map.of("Cookie", "JSESSIONID=" + pre));
    assertThat(landing.statusCode()).isEqualTo(302);
    assertThat(BffTestSessions.location(landing)).startsWith(BASE_B + "/");
    String rotated = BffTestSessions.cookie(landing, "JSESSIONID");
    assertThat(rotated).isNotNull().isNotEqualTo(pre);

    // The session B created works on A with no second login.
    BffTestSessions.Session session = new BffTestSessions.Session(rotated, null);
    assertThat(me(BASE_A, session).get("displayName").asString()).contains("split-");
    assertThat(me(BASE_B, session).get("displayName").asString()).contains("split-");
  }

  @Test
  void challengeIssuedOnAConsumesExactlyOnceFromAnywhere() throws Exception {
    BffTestSessions.Session session = login("unlock-" + suffix());
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);

    HttpResponse<String> challenge = get(BASE_A + "/api/bff/holder/challenge", session);
    assertThat(challenge.statusCode()).isEqualTo(200);
    String value = mapper.readTree(challenge.body()).get("challenge").asString();
    String proof = IssuanceFixtures.proofOver(
        holder,
        "holder-unlock/v1\n" + value + "\n" + IssuanceFixtures.thumbprint(holder),
        mapper);

    // Consumed on B although issued on A.
    HttpResponse<String> unlocked = postJson(
        BASE_B + "/api/bff/holder/unlock",
        session,
        Map.of(
            "holderJwk", mapper.convertValue(holder.jwk(), Map.class),
            "proof", proof,
            "challenge", value));
    assertThat(unlocked.statusCode()).isEqualTo(200);

    // The same challenge is dead on both replicas now.
    HttpResponse<String> replay = postJson(
        BASE_A + "/api/bff/holder/unlock",
        session,
        Map.of(
            "holderJwk", mapper.convertValue(holder.jwk(), Map.class),
            "proof", proof,
            "challenge", value));
    assertThat(replay.statusCode()).isEqualTo(400);

    // ... while the unlock grant itself is visible on both replicas.
    assertThat(get(BASE_A + "/api/bff/holder/cases", session).statusCode()).isEqualTo(200);
    assertThat(get(BASE_B + "/api/bff/holder/cases", session).statusCode()).isEqualTo(200);
  }

  @Test
  void revocationOnAIsHonoredImmediatelyOnB() throws Exception {
    String subject = "revoke-" + suffix();
    BffTestSessions.Session session = login(subject);
    assertThat(me(BASE_B, session).get("displayName").asString()).contains(subject);

    UUID membershipId =
        memberships.findBySubject(STUB.issuer(), subject).orElseThrow().id();
    memberships.revoke(membershipId);

    assertThat(get(BASE_B + "/api/bff/me", session).statusCode()).isEqualTo(401);
    assertThat(get(BASE_A + "/api/bff/me", session).statusCode()).isEqualTo(401);
  }

  @Test
  void logoutOnAKillsTheSessionOnB() throws Exception {
    BffTestSessions.Session session = login("logout-" + suffix());
    assertThat(me(BASE_B, session).get("displayName").asString()).isNotBlank();

    HttpRequest armed = HttpRequest.newBuilder(URI.create(BASE_A + "/api/bff/logout"))
        .timeout(Duration.ofSeconds(30))
        .header(
            "Cookie", "JSESSIONID=" + session.jsessionid() + "; XSRF-TOKEN=" + session.xsrf())
        .header("X-XSRF-TOKEN", session.xsrf())
        .POST(HttpRequest.BodyPublishers.noBody())
        .build();
    HttpResponse<String> done = http.send(armed, HttpResponse.BodyHandlers.ofString());
    assertThat(done.statusCode()).isEqualTo(200);

    assertThat(get(BASE_B + "/api/bff/me", session).statusCode()).isEqualTo(401);
    assertThat(get(BASE_A + "/api/bff/me", session).statusCode()).isEqualTo(401);
  }

  private BffTestSessions.Session login(String subject) throws Exception {
    return BffTestSessions.login(
        http, mapper, BASE_A, STUB,
        new StubOpenIdProvider.Script(subject, List.of("sovra-members"), "sovra-demo", List.of("pwd")));
  }

  private JsonNode me(String base, BffTestSessions.Session session) throws Exception {
    HttpResponse<String> response = get(base + "/api/bff/me", session);
    assertThat(response.statusCode()).isEqualTo(200);
    return mapper.readTree(response.body());
  }

  private HttpResponse<String> get(String url, BffTestSessions.Session session) throws Exception {
    return BffTestSessions.get(http, url, Map.of("Cookie", "JSESSIONID=" + session.jsessionid()));
  }

  private HttpResponse<String> postJson(String url, BffTestSessions.Session session, Map<String, Object> body)
      throws Exception {
    HttpRequest request = HttpRequest.newBuilder(URI.create(url))
        .timeout(Duration.ofSeconds(30))
        .header("Cookie", "JSESSIONID=" + session.jsessionid() + "; XSRF-TOKEN=" + session.xsrf())
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
