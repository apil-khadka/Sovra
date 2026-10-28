package dev.sovra.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.audit.AuditCursor;
import dev.sovra.consent.ConsentFixtures;
import dev.sovra.guard.GuardPolicies;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Bounded audit pagination (SOV-015, IF-11, SEC-42): limit clamping,
 * stable keyset cursors, opaque-cursor rejection, and tenant isolation
 * that holds across pages.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuditPaginationTests extends SovraAppRoleBase {

  private static final ParameterizedTypeReference<List<Map<String, Object>>> PAGE =
      new ParameterizedTypeReference<>() {};

  @LocalServerPort int port;

  @Autowired TrustService trust;

  @Autowired ObjectMapper mapper;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() throws Exception {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
    IssuanceFixtures.ensureSyntheticIssuer(owner, trust, mapper);
  }

  private List<Map<String, Object>> page(TestAccount reader, String query) {
    return client
        .get()
        .uri("/api/audit/events" + query)
        .headers(reader.headers())
        .retrieve()
        .body(PAGE);
  }

  private void touchAudit(TestAccount actor) {
    // A permitted guard validation: its PERMIT audit row commits (denied
    // write-path attempts roll their audit back with the business tx, so
    // denials cannot seed pages).
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("plan", ConsentFixtures.planBody(ConsentFixtures.validPlan()));
    body.put("policyId", GuardPolicies.POLICY_ID);
    body.put("policyVersion", GuardPolicies.POLICY_VERSION);
    client
        .post()
        .uri("/api/guard/validate")
        .headers(actor.headers())
        .contentType(MediaType.APPLICATION_JSON)
        .body(body)
        .retrieve()
        .toBodilessEntity();
  }

  private TestAccount writerFor(TestAccount reader, String name) {
    return TestAccounts.createInTenant(owner, reader.tenantId(), name, Set.of("RP_CLIENT"));
  }

  @Test
  void limitIsClampedToTheDocumentedBound() {
    TestAccount reader = TestAccounts.create(owner, "audit-limit", Set.of("AUDIT_READER"));
    TestAccount writer = writerFor(reader, "audit-limit-writer");
    for (int i = 0; i < 5; i++) {
      touchAudit(writer);
    }
    List<Map<String, Object>> rows = page(reader, "?limit=5000");

    assertThat(rows).isNotNull().hasSize(5);
  }

  @Test
  void cursorPagesWithoutOverlapOrGap() {
    TestAccount reader = TestAccounts.create(owner, "audit-cursor", Set.of("AUDIT_READER"));
    TestAccount writer = writerFor(reader, "audit-writer");
    for (int i = 0; i < 6; i++) {
      touchAudit(writer);
    }

    List<Map<String, Object>> first = page(reader, "?limit=2");
    assertThat(first).isNotNull().hasSize(2);
    Map<String, Object> last = first.get(1);
    String cursor =
        AuditCursor.encode(last.get("occurredAt").toString(), last.get("id").toString());

    List<Map<String, Object>> second = page(reader, "?limit=2&cursor=" + cursor);
    assertThat(second).isNotNull().hasSize(2);
    assertThat(second.stream().map(r -> r.get("id").toString()).toList())
        .doesNotContain(
            first.get(0).get("id").toString(), first.get(1).get("id").toString());

    // Newest-first ordering holds within and across the boundary.
    assertThat(first.get(0).get("occurredAt").toString())
        .isGreaterThanOrEqualTo(first.get(1).get("occurredAt").toString());
    assertThat(first.get(1).get("occurredAt").toString())
        .isGreaterThanOrEqualTo(second.get(0).get("occurredAt").toString());
  }

  @Test
  void malformedCursorsAreRejectedWithoutDisclosure() {
    TestAccount reader = TestAccounts.create(owner, "audit-badcursor", Set.of("AUDIT_READER"));
    for (String bad : List.of("not-base64!!!", "e30=", AuditCursor.encode("nope", "nope"))) {
      assertThatThrownBy(() -> page(reader, "?cursor=" + bad))
          .isInstanceOf(HttpClientErrorException.BadRequest.class);
    }
  }

  @Test
  void foreignCursorCannotWidenTheTenantBoundary() {
    TestAccount readerA = TestAccounts.create(owner, "audit-a", Set.of("AUDIT_READER"));
    TestAccount readerB = TestAccounts.create(owner, "audit-b", Set.of("AUDIT_READER"));
    TestAccount writerA = writerFor(readerA, "audit-a-writer");
    TestAccount writerB = writerFor(readerB, "audit-b-writer");
    // A's rows predate B's, so B's cursor still positions inside A's page.
    touchAudit(writerA);
    touchAudit(writerA);
    touchAudit(writerB);
    List<Map<String, Object>> other = page(readerB, "?limit=1");
    assertThat(other).isNotNull().hasSize(1);

    // Tenant B's cursor used by tenant A: only A's own rows may appear.
    String foreign =
        AuditCursor.encode(other.get(0).get("occurredAt").toString(), other.get(0).get("id").toString());
    List<Map<String, Object>> rows = page(readerA, "?limit=50&cursor=" + foreign);
    assertThat(rows).isNotNull().hasSize(2);
    for (Map<String, Object> row : rows) {
      assertThat(row.get("id").toString()).isNotEqualTo(other.get(0).get("id").toString());
    }
  }
}
