package dev.sovra.tenancy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraPostgresBase;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Statement deadlines (PROD-007): with a 50ms statement timeout,
 * a 5-second sleep is cancelled by PostgreSQL and surfaces as a
 * typed {@link QueryTimeoutException} — never a wedged pool slot.
 * Production runs the same mechanism at 25s via
 * {@code connection-init-sql}.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.NONE,
    properties = "spring.datasource.hikari.connection-init-sql=SET statement_timeout = '50ms'")
class JdbcTimeoutTests extends SovraPostgresBase {

  // The application's own pool: connection-init-sql applies to app
  // connections, not to the test-managed pools.
  @Autowired DataSource dataSource;

  @Test
  void runawayStatementsAreCancelledAndTyped() {
    JdbcTemplate jdbc = new JdbcTemplate(dataSource);
    assertThatThrownBy(() -> jdbc.queryForObject("SELECT pg_sleep(5)", Double.class))
        .isInstanceOf(QueryTimeoutException.class);
    // The pool slot is freed: the next statement runs normally.
    assertThat(jdbc.queryForObject("SELECT 1", Integer.class)).isEqualTo(1);
  }
}
