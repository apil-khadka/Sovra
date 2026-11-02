package dev.sovra.web;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.planning.AiBudgetExhaustedException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * Metered-spend exhaustion is a typed 429 (PROD-012): the fleet AI
 * budget maps to retryable {@code ai_budget_exhausted} with an honest
 * Retry-After to the UTC-midnight reset — distinct from rate_limited
 * (request-rate) and quota_exceeded (storage), never a bare 500.
 */
class AiBudgetMappingTests {

  ApiExceptionHandler handler = new ApiExceptionHandler();

  @Test
  void exhaustionMapsToRetryableBudgetDenial() {
    MockHttpServletRequest legacy = new MockHttpServletRequest();
    ResponseEntity<Object> plain = handler.aiBudgetExhausted(legacy);
    assertThat(plain.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    assertThat(plain.getBody().toString()).contains("ai_budget_exhausted");
    assertThat(retryAfter(plain)).isBetween(1L, 86_400L);

    MockHttpServletRequest problem = new MockHttpServletRequest();
    problem.addHeader("Accept", "application/problem+json");
    ResponseEntity<Object> shaped = handler.aiBudgetExhausted(problem);
    assertThat(shaped.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    assertThat(shaped.getBody().toString())
        .contains("ai_budget_exhausted")
        .contains("retryable=true");
    assertThat(retryAfter(shaped)).isBetween(1L, 86_400L);
  }

  @Test
  void handlerCoversOnlyTheBudgetException() throws Exception {
    Class<?>[] handled =
        ApiExceptionHandler.class
            .getMethod("aiBudgetExhausted", jakarta.servlet.http.HttpServletRequest.class)
            .getAnnotation(org.springframework.web.bind.annotation.ExceptionHandler.class)
            .value();
    assertThat(handled).containsExactly(AiBudgetExhaustedException.class);
  }

  private long retryAfter(ResponseEntity<Object> response) {
    return Long.parseLong(response.getHeaders().getFirst("Retry-After"));
  }
}
