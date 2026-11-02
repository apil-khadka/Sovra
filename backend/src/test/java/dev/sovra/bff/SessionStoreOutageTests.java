package dev.sovra.bff;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import jakarta.servlet.FilterChain;
import java.sql.SQLException;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.session.web.http.CookieHttpSessionIdResolver;
import org.springframework.session.web.http.SessionRepositoryFilter;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Session-store outage behavior (PROD-003): when the shared store
 * is unreachable, BFF requests fail loudly instead of proceeding —
 * the application chain is never invoked, so no request can be
 * mis-authenticated or silently treated as anonymous.
 */
class SessionStoreOutageTests {

  @Test
  void deadStoreKeepsRequestsOutOfTheApplication() throws Exception {
    DataSource dead = mock(DataSource.class);
    when(dead.getConnection()).thenThrow(new SQLException("session store unreachable"));
    TransactionTemplate transactions = new TransactionTemplate(new DataSourceTransactionManager(dead));
    JdbcIndexedSessionRepository repository = new JdbcIndexedSessionRepository(
        new JdbcTemplate(dead), transactions);
    SessionRepositoryFilter<?> filter = new SessionRepositoryFilter<>(repository);
    // The production cookie contract: JSESSIONID, not Spring
    // Session's default SESSION name.
    CookieHttpSessionIdResolver ids = new CookieHttpSessionIdResolver();
    ids.setCookieSerializer(new SessionSharingConfig().cookieSerializer());
    filter.setHttpSessionIdResolver(ids);

    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/bff/me");
    request.setCookies(new jakarta.servlet.http.Cookie("JSESSIONID", "forged-or-stale-id"));
    MockHttpServletResponse response = new MockHttpServletResponse();
    // The application reads its session exactly like BffSessionFilter
    // does; the read — not the filter entry — hits the dead store.
    AtomicBoolean pastSessionRead = new AtomicBoolean(false);
    FilterChain chain = (req, res) -> {
      ((jakarta.servlet.http.HttpServletRequest) req).getSession(false);
      pastSessionRead.set(true);
    };

    assertThatThrownBy(() -> filter.doFilter(request, response, chain))
        .isInstanceOf(TransactionException.class);
    assertThat(pastSessionRead).isFalse();
  }

  @Test
  void sessionlessRequestsProceedDespiteTheOutage() throws Exception {
    DataSource dead = mock(DataSource.class);
    when(dead.getConnection()).thenThrow(new SQLException("session store unreachable"));
    JdbcIndexedSessionRepository repository = new JdbcIndexedSessionRepository(
        new JdbcTemplate(dead), new TransactionTemplate());
    SessionRepositoryFilter<?> filter = new SessionRepositoryFilter<>(repository);

    // No cookie and no session access: the stateless machine chain
    // never touches the store, outage or not.
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/health");
    MockHttpServletResponse response = new MockHttpServletResponse();
    AtomicBoolean chainReached = new AtomicBoolean(false);
    FilterChain chain = (req, res) -> chainReached.set(true);

    filter.doFilter(request, response, chain);
    assertThat(chainReached).isTrue();
  }
}
