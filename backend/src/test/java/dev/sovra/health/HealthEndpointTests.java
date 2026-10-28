package dev.sovra.health;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraPostgresBase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class HealthEndpointTests extends SovraPostgresBase {

  @LocalServerPort int port;

  RestClient client;

  @BeforeEach
  void setupClient() {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
  }

  @Test
  void healthIsPublicAndReportsBuildIdentity() {
    HealthController.HealthStatus body =
        client.get().uri("/api/health").retrieve().body(HealthController.HealthStatus.class);
    assertThat(body).isNotNull();
    assertThat(body.status()).isEqualTo("UP");
    assertThat(body.service()).isEqualTo("sovra-backend");
    assertThat(body.version()).isEqualTo("0.1.0");
  }

  @Test
  void actuatorHealthRequiresAuthentication() {
    assertThatThrownBy(
            () -> client.get().uri("/actuator/health").retrieve().toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
  }

  @Test
  void actuatorInternalsAreNotPubliclyReachable() {
    // Security rejects unauthenticated requests before MVC routing, so internals
    // are unreachable regardless of exposure config. Verifying non-exposure for
    // authenticated callers needs service credentials (SOV-006).
    assertThatThrownBy(() -> client.get().uri("/actuator/env").retrieve().toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
  }
}
