package dev.sovra.web;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.CannotGetJdbcConnectionException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.transaction.TransactionTimedOutException;

/**
 * Deadline failures are typed 503s (PROD-007): pool exhaustion and
 * statement/transaction timeouts map to retryable
 * {@code dependency_unavailable} in both error shapes — never a
 * bare 500.
 */
class DeadlineMappingTests {

  ApiExceptionHandler handler = new ApiExceptionHandler();

  @Test
  void timeoutsMapToRetryableDependencyFailures() {
    MockHttpServletRequest legacy = new MockHttpServletRequest();
    ResponseEntity<Object> pool =
        handler.deadlineExceeded(legacy);
    assertThat(pool.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    assertThat(pool.getBody().toString()).contains("dependency_unavailable");

    MockHttpServletRequest problem = new MockHttpServletRequest();
    problem.addHeader("Accept", "application/problem+json");
    ResponseEntity<Object> timeout = handler.deadlineExceeded(problem);
    assertThat(timeout.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    assertThat(timeout.getBody().toString())
        .contains("dependency_unavailable")
        .contains("retryable=true");
  }

  @Test
  void handlerCoversAllThreeDeadlineExceptions() throws Exception {
    // The mapping is by annotation: pool exhaustion, statement
    // timeout, and transaction timeout must all route here — and
    // nothing broader (a bare DataAccessException entry would let
    // SQL bugs hide behind "retryable").
    Class<?>[] handled = ApiExceptionHandler.class
        .getMethod("deadlineExceeded", jakarta.servlet.http.HttpServletRequest.class)
        .getAnnotation(org.springframework.web.bind.annotation.ExceptionHandler.class)
        .value();
    assertThat(handled)
        .containsExactlyInAnyOrder(
            QueryTimeoutException.class,
            CannotGetJdbcConnectionException.class,
            TransactionTimedOutException.class);
  }
}
