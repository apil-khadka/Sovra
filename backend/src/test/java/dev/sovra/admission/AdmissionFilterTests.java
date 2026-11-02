package dev.sovra.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import dev.sovra.SovraPostgresBase;
import dev.sovra.auth.ServiceAccountAuthentication;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Role;
import jakarta.servlet.FilterChain;
import java.sql.SQLException;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Admission decisions (PROD-006): per-principal and per-tenant
 * budgets with hot-tenant isolation, coarse anonymous buckets,
 * explicit 429/503 shapes with retry guidance, fail-closed limiter
 * outage, and non-blocking in-flight ceilings. The filter runs
 * directly with hand-set caller contexts and tiny test budgets, so
 * every denial is deterministic; AdmissionHttpTests proves the
 * chain wiring end to end.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AdmissionFilterTests extends SovraPostgresBase {

  static final UUID TENANT_A = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
  static final UUID TENANT_B = UUID.fromString("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");

  AdmissionProperties tiny = new AdmissionProperties(
      new AdmissionProperties.Bucket(2.0, 0.01),
      new AdmissionProperties.Bucket(3.0, 0.01),
      new AdmissionProperties.Bucket(2.0, 0.01),
      new AdmissionProperties.Bucket(100.0, 10.0),
      new AdmissionProperties.Bucket(100.0, 10.0),
      new AdmissionProperties.Bucket(100.0, 10.0),
      new AdmissionProperties.InFlight(100, 100, 100),
      new AdmissionProperties.Bodies(1024L, 2048L));

  JdbcRateLimiter limiter;
  InFlightGuard guard;
  AdmissionFilter filter;
  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    limiter = new JdbcRateLimiter(appRoleDataSource());
    guard = new InFlightGuard(tiny);
    filter = new AdmissionFilter(limiter, tiny, guard);
    owner = new JdbcTemplate(ownerDataSource());
    owner.update("DELETE FROM rate_limit_bucket");
  }

  @AfterEach
  void clear() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void spentPrincipalBudgetRejectsWithRetryGuidance() throws Exception {
    ServiceAccountPrincipal caller = principal(TENANT_A);
    assertThat(call("/api/whoami", caller)).isEqualTo(200);
    assertThat(call("/api/whoami", caller)).isEqualTo(200);
    MockHttpServletResponse denied = callRaw("/api/whoami", caller, null);
    assertThat(denied.getStatus()).isEqualTo(429);
    assertThat(denied.getHeader("Retry-After")).isNotNull();
    assertThat(denied.getContentAsString()).contains("rate_limited");
  }

  @Test
  void problemClientsGetProblemDenials() throws Exception {
    ServiceAccountPrincipal caller = principal(TENANT_A);
    assertThat(call("/api/whoami", caller)).isEqualTo(200);
    assertThat(call("/api/whoami", caller)).isEqualTo(200);
    MockHttpServletResponse denied = callRaw("/api/whoami", caller, "application/problem+json");
    assertThat(denied.getStatus()).isEqualTo(429);
    assertThat(denied.getContentType()).contains("application/problem+json");
    assertThat(denied.getContentAsString())
        .contains("\"code\":\"rate_limited\"")
        .contains("\"retryable\":true");
  }

  @Test
  void hotTenantsCannotStarveOtherTenants() throws Exception {
    ServiceAccountPrincipal hot1 = principal(TENANT_A);
    ServiceAccountPrincipal hot2 = principal(TENANT_A);
    // Tenant A burns its whole shared budget across two principals.
    assertThat(call("/api/whoami", hot1)).isEqualTo(200);
    assertThat(call("/api/whoami", hot1)).isEqualTo(200);
    assertThat(call("/api/whoami", hot2)).isEqualTo(200);
    assertThat(call("/api/whoami", hot2)).isEqualTo(429);
    // Tenant B is untouched: separate buckets, separate fate.
    assertThat(call("/api/whoami", principal(TENANT_B))).isEqualTo(200);
  }

  @Test
  void anonymousLoginBurnsTheSharedLoginBucket() throws Exception {
    assertThat(call("/oauth2/authorization/sovra", null)).isEqualTo(200);
    assertThat(call("/oauth2/authorization/sovra", null)).isEqualTo(200);
    MockHttpServletResponse denied = callRaw("/login/oauth2/code/sovra", null, null);
    assertThat(denied.getStatus()).isEqualTo(429);
    assertThat(denied.getHeader("Retry-After")).isNotNull();
  }

  @Test
  void cheapPublicContentSkipsTheBuckets() throws Exception {
    assertThat(call("/index.html", null)).isEqualTo(200);
    assertThat(call("/api/discovery", null)).isEqualTo(200);
    assertThat(countRows()).isEqualTo(0);
  }

  @Test
  void limiterOutageFailsClosedWithRetryGuidance() throws Exception {
    DataSource dead = mock(DataSource.class);
    when(dead.getConnection()).thenThrow(new SQLException("limiter store down"));
    AdmissionFilter outage = new AdmissionFilter(new JdbcRateLimiter(dead), tiny, guard);
    AtomicBoolean reached = new AtomicBoolean(false);
    MockHttpServletRequest request = request("/api/whoami");
    MockHttpServletResponse response = new MockHttpServletResponse();
    as(principal(TENANT_A));
    outage.doFilter(request, response, (req, res) -> reached.set(true));
    assertThat(response.getStatus()).isEqualTo(503);
    assertThat(response.getContentAsString()).contains("limiter_unavailable");
    assertThat(response.getHeader("Retry-After")).isEqualTo("5");
    assertThat(reached).isFalse();
  }

  @Test
  void fullGroupsFailFastAndPermitsAlwaysRelease() throws Exception {
    AdmissionProperties none = new AdmissionProperties(
        tiny.principal(), tiny.tenant(), tiny.anonymousLogin(), tiny.anonymousProtocol(),
        tiny.probeReady(), tiny.probeHealth(),
        new AdmissionProperties.InFlight(0, 0, 0), tiny.bodies());
    AdmissionFilter full = new AdmissionFilter(limiter, none, new InFlightGuard(none));
    MockHttpServletResponse response = new MockHttpServletResponse();
    as(principal(TENANT_A));
    full.doFilter(request("/api/whoami"), response, (req, res) -> {});
    assertThat(response.getStatus()).isEqualTo(503);
    assertThat(response.getContentAsString()).contains("overloaded");

    // And the shared guard releases every acquired permit: a
    // single-permit group serves sequential requests forever.
    AdmissionProperties one = new AdmissionProperties(
        new AdmissionProperties.Bucket(100.0, 100.0),
        new AdmissionProperties.Bucket(100.0, 100.0),
        tiny.anonymousLogin(), tiny.anonymousProtocol(),
        tiny.probeReady(), tiny.probeHealth(),
        new AdmissionProperties.InFlight(1, 1, 1), tiny.bodies());
    AdmissionFilter serial = new AdmissionFilter(limiter, one, new InFlightGuard(one));
    as(principal(TENANT_A));
    for (int i = 0; i < 5; i++) {
      AtomicBoolean reached = new AtomicBoolean(false);
      MockHttpServletResponse ok = new MockHttpServletResponse();
      serial.doFilter(request("/api/whoami"), ok, (req, res) -> reached.set(true));
      assertThat(ok.getStatus()).isEqualTo(200);
      assertThat(reached).isTrue();
    }
  }

  @Test
  void deniedRequestsNeverReachTheApplication() throws Exception {
    ServiceAccountPrincipal caller = principal(TENANT_A);
    assertThat(call("/api/whoami", caller)).isEqualTo(200);
    assertThat(call("/api/whoami", caller)).isEqualTo(200);
    AtomicBoolean reached = new AtomicBoolean(false);
    MockHttpServletResponse response = new MockHttpServletResponse();
    as(caller);
    filter.doFilter(request("/api/whoami"), response, (req, res) -> reached.set(true));
    assertThat(response.getStatus()).isEqualTo(429);
    assertThat(reached).isFalse();
  }

  private ServiceAccountPrincipal principal(UUID tenantId) {
    return new ServiceAccountPrincipal(UUID.randomUUID(), tenantId, "test", Set.of(Role.AUDIT_READER));
  }

  private void as(ServiceAccountPrincipal caller) {
    SecurityContextHolder.getContext().setAuthentication(new ServiceAccountAuthentication(caller));
  }

  private MockHttpServletRequest request(String path) {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
    request.setServletPath(path);
    return request;
  }

  private int call(String path, ServiceAccountPrincipal caller) throws Exception {
    return callRaw(path, caller, null).getStatus();
  }

  private MockHttpServletResponse callRaw(String path, ServiceAccountPrincipal caller, String accept)
      throws Exception {
    if (caller == null) {
      SecurityContextHolder.clearContext();
    } else {
      as(caller);
    }
    MockHttpServletRequest request = request(path);
    if (accept != null) {
      request.addHeader("Accept", accept);
    }
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = (req, res) -> ((MockHttpServletResponse) res).setStatus(200);
    filter.doFilter(request, response, chain);
    return response;
  }

  private int countRows() {
    Integer count = owner.queryForObject("SELECT COUNT(*) FROM rate_limit_bucket", Integer.class);
    return count == null ? 0 : count;
  }
}
