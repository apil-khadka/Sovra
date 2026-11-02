package dev.sovra.admission;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

/**
 * Admission wiring end to end (PROD-006): the filters run inside
 * the real chains with production-shaped grants and default
 * budgets. Buckets are cleared per test so hammer assertions are
 * deterministic despite the shared container database.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {
      // Tiny budgets keep hammer assertions fast and deterministic;
      // the slow live checks would otherwise refill defaults mid-run.
      "sovra.admission.probe-ready.capacity=5",
      "sovra.admission.probe-ready.rate-per-second=0.1",
      "sovra.admission.bodies.default-max-bytes=1024"
    })
class AdmissionHttpTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    // Non-retrying factory: Apache HttpClient honors Retry-After and
    // would turn every 429 into a 10-second wait plus a 200.
    client = RestClient.builder()
        .baseUrl("http://localhost:" + port)
        .requestFactory(new org.springframework.http.client.JdkClientHttpRequestFactory())
        .build();
    owner = new JdbcTemplate(ownerDataSource());
    owner.update("DELETE FROM rate_limit_bucket");
  }

  @Test
  void readinessFloodGetsExplicit429sWithRetryGuidance() {
    assertThat(client.get().uri("/api/health/ready").retrieve().toBodilessEntity().getStatusCode())
        .isEqualTo(HttpStatus.OK);
    int limited = 0;
    String retryAfter = null;
    for (int i = 0; i < 30; i++) {
      try {
        client.get().uri("/api/health/ready").retrieve().toBodilessEntity();
      } catch (HttpClientErrorException.TooManyRequests e) {
        limited++;
        retryAfter = e.getResponseHeaders() == null
            ? null
            : e.getResponseHeaders().getFirst("Retry-After");
        assertThat(e.getResponseBodyAsString()).contains("rate_limited");
      }
    }
    // 5-burst test bucket: the flood always trips it.
    assertThat(limited).isGreaterThan(0);
    assertThat(retryAfter).isNotNull();
  }

  @Test
  void problemClientsGetProblemDenials() {
    var problem = org.springframework.http.MediaType.parseMediaType("application/problem+json");
    int limited = 0;
    for (int i = 0; i < 30; i++) {
      try {
        client.get().uri("/api/health/ready").accept(problem).retrieve().toBodilessEntity();
      } catch (HttpClientErrorException.TooManyRequests e) {
        limited++;
        assertThat(e.getResponseBodyAsString())
            .contains("\"code\":\"rate_limited\"")
            .contains("\"retryable\":true");
      }
    }
    assertThat(limited).isGreaterThan(0);
  }

  @Test
  void oversizedBodiesAreRejectedBeforeRouting() throws Exception {
    // Early rejection resets streaming uploaders mid-body, so the
    // wire behavior is asserted over a raw socket: headers declare
    // 3MB, the server answers 413 without waiting for the bytes.
    try (java.net.Socket socket = new java.net.Socket("localhost", port)) {
      socket.setSoTimeout(10_000);
      String head = "POST /api/whoami HTTP/1.1\r\n"
          + "Host: localhost\r\n"
          + "Content-Type: application/json\r\n"
          + "Content-Length: 3145728\r\n"
          + "Connection: close\r\n\r\n";
      socket.getOutputStream().write(head.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      socket.getOutputStream().flush();
      java.io.BufferedReader reader = new java.io.BufferedReader(
          new java.io.InputStreamReader(socket.getInputStream(), java.nio.charset.StandardCharsets.UTF_8));
      String status = reader.readLine();
      assertThat(status).startsWith("HTTP/1.1 413");
    }
  }

  @Test
  void ordinaryAuthenticatedTrafficIsUnaffected() {
    TestAccount account = TestAccounts.create(owner, "admission-ok", Set.of("AUDIT_READER"));
    var response = client.get().uri("/api/whoami").headers(account.headers()).retrieve();
    assertThat(response.toBodilessEntity().getStatusCode()).isEqualTo(HttpStatus.OK);
  }
}
