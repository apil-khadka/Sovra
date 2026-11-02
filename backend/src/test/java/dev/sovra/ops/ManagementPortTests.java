package dev.sovra.ops;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraAppRoleBase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

/**
 * Private management port (PROD-011): Prometheus scraping and
 * actuator health serve without credentials on the management port
 * only; the same paths on the application port stay behind
 * authentication.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {
      "management.server.port=18081",
      "sovra.instance-id=obs-mgmt"
    })
class ManagementPortTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  RestClient app;
  RestClient mgmt;

  @BeforeEach
  void setup() {
    var factory = new org.springframework.http.client.JdkClientHttpRequestFactory();
    app =
        RestClient.builder().baseUrl("http://localhost:" + port).requestFactory(factory).build();
    mgmt =
        RestClient.builder().baseUrl("http://localhost:18081").requestFactory(factory).build();
  }

  @Test
  void prometheusServesWithInstanceTag() {
    var response =
        mgmt.get().uri("/actuator/prometheus").retrieve().toEntity(String.class);
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(response.getBody()).contains("instance=\"obs-mgmt\"");
  }

  @Test
  void actuatorHealthServesOnManagementPort() {
    var response = mgmt.get().uri("/actuator/health").retrieve().toEntity(String.class);
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(response.getBody()).contains("\"UP\"");
  }

  @Test
  void actuatorStaysPrivateOnAppPort() {
    try {
      app.get().uri("/actuator/prometheus").retrieve().toBodilessEntity();
      assertThat(false).as("actuator on the app port must require auth").isTrue();
    } catch (HttpClientErrorException.Unauthorized e) {
      assertThat(e.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
  }
}
