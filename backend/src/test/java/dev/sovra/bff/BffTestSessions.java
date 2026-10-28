package dev.sovra.bff;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Shared login dance for BFF tests: the real redirect chain through
 * the stub OP (authorize, approve, callback), with PKCE, fixation
 * rotation, and CSRF-cookie assertions every login proves.
 */
public final class BffTestSessions {

  public record Session(String jsessionid, String xsrf) {}

  private BffTestSessions() {}

  public static HttpResponse<String> get(
      HttpClient http, String url, Map<String, String> headers) throws Exception {
    HttpRequest.Builder request =
        HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(30)).GET();
    headers.forEach(request::header);
    return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
  }

  public static String cookie(HttpResponse<?> response, String name) {
    return response.headers().allValues("set-cookie").stream()
        .filter(raw -> raw.startsWith(name + "="))
        .map(raw -> raw.substring(name.length() + 1).split(";", 2)[0])
        .findFirst()
        .orElse(null);
  }

  public static String location(HttpResponse<?> response) {
    return response.headers().firstValue("location").orElse("");
  }

  /**
   * Full login dance. Returns the landing Location: the app root on
   * success, {@code /?auth_error=} on denial.
   */
  public static String dance(HttpClient http, String base, Map<String, String> jar)
      throws Exception {
    HttpResponse<String> start = get(http, base + "/oauth2/authorization/sovra", Map.of());
    assertThat(start.statusCode()).isEqualTo(302);
    String authorizeUrl = location(start);
    assertThat(authorizeUrl).contains("code_challenge=").contains("code_challenge_method=S256");
    jar.put("pre", cookie(start, "JSESSIONID"));
    assertThat(jar.get("pre")).isNotNull();

    HttpResponse<String> approved = get(http, authorizeUrl, Map.of());
    assertThat(approved.statusCode()).isEqualTo(302);
    String callback = location(approved);
    assertThat(callback).startsWith(base + "/login/oauth2/code/sovra");

    HttpResponse<String> landing =
        get(http, callback, Map.of("Cookie", "JSESSIONID=" + jar.get("pre")));
    assertThat(landing.statusCode()).isEqualTo(302);
    String rotated = cookie(landing, "JSESSIONID");
    if (rotated != null) {
      jar.put("session", rotated);
    }
    return location(landing);
  }

  /** Successful login plus first session read; proves the rotation, PKCE, and CSRF cookie. */
  public static Session login(
      HttpClient http,
      ObjectMapper mapper,
      String base,
      StubOpenIdProvider stub,
      StubOpenIdProvider.Script script) throws Exception {
    stub.script(script);
    Map<String, String> jar = new java.util.HashMap<>();
    String landing = dance(http, base, jar);
    assertThat(landing).isEqualTo(base + "/");
    assertThat(jar.get("session")).isNotNull().isNotEqualTo(jar.get("pre"));
    assertThat(stub.pkceVerified()).isTrue();
    assertThat(stub.lastChallengeMethod()).isEqualTo("S256");
    HttpResponse<String> me = get(
        http, base + "/api/bff/me", Map.of("Cookie", "JSESSIONID=" + jar.get("session")));
    assertThat(me.statusCode()).isEqualTo(200);
    return new Session(jar.get("session"), cookie(me, "XSRF-TOKEN"));
  }

  public static JsonNode me(HttpClient http, ObjectMapper mapper, String base, Session session)
      throws Exception {
    HttpResponse<String> response = get(
        http, base + "/api/bff/me", Map.of("Cookie", "JSESSIONID=" + session.jsessionid()));
    assertThat(response.statusCode()).isEqualTo(200);
    return mapper.readTree(response.body());
  }
}
