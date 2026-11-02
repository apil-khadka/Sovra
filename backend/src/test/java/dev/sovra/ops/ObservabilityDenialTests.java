package dev.sovra.ops;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraAppRoleBase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

/**
 * Admission denials carry the request correlation (PROD-011): a
 * rate-limited caller gets its own request id back in both the
 * header and the problem payload, so the denial joins to logs.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {
      "sovra.admission.probe-ready.capacity=3",
      "sovra.admission.probe-ready.rate-per-second=0.1"
    })
class ObservabilityDenialTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    client = RestClient.builder()
        .baseUrl("http://localhost:" + port)
        .requestFactory(new org.springframework.http.client.JdkClientHttpRequestFactory())
        .build();
    owner = new JdbcTemplate(ownerDataSource());
    owner.update("DELETE FROM rate_limit_bucket");
  }

  @Test
  void rateLimitDenialEchoesRequestId() {
    String requestId = "denial-trace-7";
    boolean limited = false;
    for (int i = 0; i < 30 && !limited; i++) {
      try {
        client.get()
            .uri("/api/health/ready")
            .header("X-Request-Id", requestId)
            .accept(MediaType.parseMediaType("application/problem+json"))
            .retrieve()
            .toBodilessEntity();
      } catch (HttpClientErrorException.TooManyRequests e) {
        limited = true;
        assertThat(e.getResponseHeaders().getFirst("X-Request-Id")).isEqualTo(requestId);
        assertThat(e.getResponseBodyAsString())
            .contains("\"correlationId\":\"" + requestId + "\"");
      }
    }
    assertThat(limited).as("3-burst probe bucket must trip").isTrue();
  }
}
