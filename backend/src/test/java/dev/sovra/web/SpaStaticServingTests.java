package dev.sovra.web;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraAppRoleBase;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

/**
 * Packaged SPA delivery (SOV-041): the backend origin serves the
 * built bundle — entry HTML, hashed assets, history fallback —
 * while the API, auth, and error surfaces keep their exact
 * behavior. Fixtures live under a test-only static location so no
 * other suite observes them; every other context still 404s these
 * paths exactly as before.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
    properties = {
      "server.port=18084",
      "spring.web.resources.static-locations=classpath:/spa-packaged/"
    })
// Frees this fixed-port context (and its JDBC pool) after the class: with six such
// contexts the shared test Postgres runs out of connection slots otherwise.
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class SpaStaticServingTests extends SovraAppRoleBase {

  private static final String BASE = "http://localhost:18084";

  HttpClient http;

  @BeforeEach
  void setup() {
    http =
        HttpClient.newBuilder()
            .followRedirects(Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(10))
            .build();
  }

  private HttpResponse<String> get(String path) throws Exception {
    HttpRequest request =
        HttpRequest.newBuilder(URI.create(BASE + path)).timeout(Duration.ofSeconds(10)).GET().build();
    return http.send(request, HttpResponse.BodyHandlers.ofString());
  }

  private static String header(HttpResponse<?> response, String name) {
    return response.headers().firstValue(name).orElse("");
  }

  @Test
  void rootServesEntryHtmlWithoutCaching() throws Exception {
    HttpResponse<String> response = get("/");
    assertThat(response.statusCode()).isEqualTo(200);
    assertThat(header(response, "Content-Type")).contains("text/html");
    assertThat(response.body()).contains("spa-packaged-fixture");
    assertThat(header(response, "Cache-Control")).contains("no-store");
  }

  @Test
  void nestedHistoryRouteFallsBackToEntry() throws Exception {
    HttpResponse<String> response = get("/consent/review");
    assertThat(response.statusCode()).isEqualTo(200);
    assertThat(response.body()).contains("spa-packaged-fixture");
  }

  @Test
  void hashedAssetServesImmutable() throws Exception {
    HttpResponse<String> response = get("/assets/app-fixture.js");
    assertThat(response.statusCode()).isEqualTo(200);
    assertThat(response.body()).contains("spa-packaged-asset-fixture");
    assertThat(header(response, "Cache-Control")).contains("immutable");
  }

  @Test
  void apiControllerKeepsPrecedenceOverStatic() throws Exception {
    HttpResponse<String> response = get("/api/health");
    assertThat(response.statusCode()).isEqualTo(200);
    assertThat(header(response, "Content-Type")).contains("application/json");
    assertThat(response.body()).contains("\"UP\"");
  }

  @Test
  void anonymousApiStaysUnauthorizedInsteadOfFallback() throws Exception {
    assertThat(get("/api/does-not-exist").statusCode()).isEqualTo(401);
    assertThat(get("/API/health").statusCode()).isEqualTo(401);
  }

  @Test
  void authSurfacesStayReserved() throws Exception {
    assertThat(get("/oauth2/authorization/sovra").statusCode()).isEqualTo(401);
    assertThat(get("/login/oauth2/code/sovra").statusCode()).isEqualTo(401);
  }

  @Test
  void missingFileStays404WithoutFallback() throws Exception {
    assertThat(get("/missing-fixture.js").statusCode()).isEqualTo(404);
  }

  @Test
  void spaMutationStaysAuthenticated() throws Exception {
    HttpRequest request =
        HttpRequest.newBuilder(URI.create(BASE + "/consent"))
            .timeout(Duration.ofSeconds(10))
            .POST(HttpRequest.BodyPublishers.noBody())
            .build();
    HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
    assertThat(response.statusCode()).isEqualTo(401);
  }
}
