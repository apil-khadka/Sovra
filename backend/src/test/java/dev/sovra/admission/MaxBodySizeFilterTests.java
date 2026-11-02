package dev.sovra.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import jakarta.servlet.ServletInputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Ingress byte budgets (PROD-006): declared over-limit bodies are
 * rejected without reading, streamed bodies are cut off mid-read
 * before domain code can allocate for them, and document paths
 * carry the larger budget.
 */
class MaxBodySizeFilterTests {

  AdmissionProperties props = new AdmissionProperties(
      null, null, null, null, null, null, null,
      new AdmissionProperties.Bodies(16L, 64L));
  MaxBodySizeFilter filter = new MaxBodySizeFilter(props);

  @Test
  void declaredOverLimitBodiesAreRejectedUnread() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/whoami");
    request.setServletPath("/api/whoami");
    request.setContent(new byte[17]);
    MockHttpServletResponse response = new MockHttpServletResponse();
    AtomicBoolean reached = new AtomicBoolean(false);

    filter.doFilter(request, response, (req, res) -> reached.set(true));

    assertThat(response.getStatus()).isEqualTo(413);
    assertThat(response.getContentAsString()).contains("body_too_large");
    assertThat(reached).isFalse();
  }

  @Test
  void documentPathsCarryTheLargerBudget() throws Exception {
    MockHttpServletRequest vault = new MockHttpServletRequest("POST", "/api/vault/objects");
    vault.setServletPath("/api/vault/objects");
    vault.setContent(new byte[17]);
    MockHttpServletResponse vaultResponse = new MockHttpServletResponse();
    AtomicBoolean vaultReached = new AtomicBoolean(false);
    filter.doFilter(vault, vaultResponse, (req, res) -> vaultReached.set(true));
    assertThat(vaultReached).isTrue();

    MockHttpServletRequest huge = new MockHttpServletRequest("POST", "/api/vault/objects");
    huge.setServletPath("/api/vault/objects");
    huge.setContent(new byte[65]);
    MockHttpServletResponse hugeResponse = new MockHttpServletResponse();
    filter.doFilter(huge, hugeResponse, (req, res) -> {});
    assertThat(hugeResponse.getStatus()).isEqualTo(413);
  }

  @Test
  void streamedBodiesAreCutOffMidRead() throws Exception {
    // Chunked uploads declare no length; the bounded stream stops
    // them at the budget instead of letting parsers allocate.
    byte[] payload = "0123456789abcdefg".getBytes(StandardCharsets.UTF_8);
    MockHttpServletRequest raw = new MockHttpServletRequest("POST", "/api/whoami");
    raw.setContent(payload);
    MaxBodySizeFilter.BoundedRequest bounded = new MaxBodySizeFilter.BoundedRequest(raw, 16);
    ServletInputStream stream = bounded.getInputStream();
    byte[] buf = new byte[32];
    assertThatThrownBy(() -> {
          while (stream.read(buf, 0, buf.length) != -1) {
            // Drain until the budget trips.
          }
        })
        .isInstanceOf(BodyTooLargeException.class);
  }

  @Test
  void bodiesWithinBudgetPassThroughIntact() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/whoami");
    request.setServletPath("/api/whoami");
    request.setContent(new byte[16]);
    MockHttpServletResponse response = new MockHttpServletResponse();
    AtomicBoolean reached = new AtomicBoolean(false);
    filter.doFilter(request, response, (req, res) -> reached.set(true));
    assertThat(reached).isTrue();
    assertThat(response.getStatus()).isEqualTo(200);
  }

  @Test
  void safeMethodsSkipTheBudget() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/whoami");
    request.setServletPath("/api/whoami");
    MockHttpServletResponse response = new MockHttpServletResponse();
    AtomicBoolean reached = new AtomicBoolean(false);
    filter.doFilter(request, response, (req, res) -> reached.set(true));
    assertThat(reached).isTrue();
  }
}
