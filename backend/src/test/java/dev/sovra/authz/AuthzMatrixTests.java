package dev.sovra.authz;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraPostgresBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.issuance.IssuanceFixtures;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthzMatrixTests extends SovraPostgresBase {

  @LocalServerPort int port;

  @Autowired DataSource dataSource;

  @Autowired EmergencyFlagService emergency;

  @Autowired ObjectMapper mapper;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
    owner.update("UPDATE emergency_flag SET enabled = FALSE WHERE id = 1");
    emergency.clearCache();
  }

  /**
   * Well-shaped issuance body. Bean validation passes, so the service's
   * authorization decision (not request shape) determines the outcome.
   */
  private Map<String, Object> issueBody() throws Exception {
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String key = "matrix-valid";
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("issuerId", IssuanceFixtures.ISSUER_ID);
    body.put("vct", IssuanceFixtures.ADULT_VCT);
    body.put("holderJwk", mapper.convertValue(holder.jwk(), Map.class));
    body.put("holderProof",
        IssuanceFixtures.proof(holder, key, IssuanceFixtures.ADULT_VCT, mapper));
    body.put("claims", Map.of("adultOver18", Boolean.TRUE));
    body.put("expiresAt", Instant.now().plusSeconds(3600).toString());
    return body;
  }

  @Test
  void unrelatedRoleIsDeniedOnPrivilegedEndpoints() throws Exception {
    TestAccount outsider =
        TestAccounts.create(owner, "matrix-outsider", Set.of("RP_CLIENT"));
    Map<String, Object> issuance = issueBody();
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/trust/proposals")
                    .headers(outsider.headers())
                    .contentType(MediaType.APPLICATION_JSON).body("{}")
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(
            () ->
                client
                    .get()
                    .uri("/api/audit/events")
                    .headers(outsider.headers())
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/issuance/credentials")
                    .headers(
                        h -> {
                          outsider.headers().accept(h);
                          h.set("Idempotency-Key", "matrix-valid");
                        })
                    .contentType(MediaType.APPLICATION_JSON).body(issuance)
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(
            () ->
                client
                    .get()
                    .uri("/api/issuance/credentials/00000000-0000-0000-0000-000000000000")
                    .headers(outsider.headers())
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
  }

  @Test
  void trustAdminCannotIssueOrReadCredentials() throws Exception {
    TestAccount admin = TestAccounts.create(owner, "matrix-admin", Set.of("TRUST_ADMIN"));
    Map<String, Object> issuance = issueBody();
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/issuance/credentials")
                    .headers(
                        h -> {
                          admin.headers().accept(h);
                          h.set("Idempotency-Key", "matrix-valid");
                        })
                    .contentType(MediaType.APPLICATION_JSON).body(issuance)
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(
            () ->
                client
                    .get()
                    .uri("/api/issuance/credentials/00000000-0000-0000-0000-000000000000")
                    .headers(admin.headers())
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
  }

  @Test
  void issuerOpsCannotChangeTrust() {
    TestAccount ops = TestAccounts.create(owner, "ops", Set.of("ISSUER_OPS"));
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/trust/proposals")
                    .headers(ops.headers())
                    .contentType(MediaType.APPLICATION_JSON).body("{}")
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Forbidden.class)
        .satisfies(
            e ->
                assertThat(((HttpClientErrorException) e).getResponseBodyAsString())
                    .contains("MISSING_ROLE"));
  }

  @Test
  void auditReaderReadsAuditButNotTrust() {
    TestAccount reader = TestAccounts.create(owner, "reader", Set.of("AUDIT_READER"));
    client.get().uri("/api/audit/events").headers(reader.headers()).retrieve().toBodilessEntity();
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/trust/proposals")
                    .headers(reader.headers())
                    .contentType(MediaType.APPLICATION_JSON).body("{}")
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
  }

  @Test
  void trustAdminReadsAudit() {
    TestAccount admin = TestAccounts.create(owner, "admin", Set.of("TRUST_ADMIN"));
    client.get().uri("/api/audit/events").headers(admin.headers()).retrieve().toBodilessEntity();
  }

  @Test
  void emergencyFlagFreezesAuthorization() {
    TestAccount admin = TestAccounts.create(owner, "frozen", Set.of("TRUST_ADMIN"));
    owner.update("UPDATE emergency_flag SET enabled = TRUE WHERE id = 1");
    emergency.clearCache();
    try {
      assertThatThrownBy(
              () ->
                  client
                      .post()
                      .uri("/api/trust/proposals")
                      .headers(admin.headers())
                      .contentType(MediaType.APPLICATION_JSON).body("{}")
                      .retrieve()
                      .toBodilessEntity())
          .isInstanceOf(HttpClientErrorException.Forbidden.class)
          .satisfies(
              e ->
                  assertThat(((HttpClientErrorException) e).getResponseBodyAsString())
                      .contains("EMERGENCY_FREEZE"));
    } finally {
      owner.update("UPDATE emergency_flag SET enabled = FALSE WHERE id = 1");
      emergency.clearCache();
    }
  }

  @Test
  void emergencyFreezeDeniesDespiteWarmPermitCache() {
    // A permitted read warms the 60-second grant cache first; the
    // freeze is checked before the cache, so it still denies (SOV-012).
    TestAccount reader = TestAccounts.create(owner, "warm-reader", Set.of("AUDIT_READER"));
    client.get().uri("/api/audit/events").headers(reader.headers()).retrieve().toBodilessEntity();
    owner.update("UPDATE emergency_flag SET enabled = TRUE WHERE id = 1");
    emergency.clearCache();
    try {
      assertThatThrownBy(
              () ->
                  client
                      .get()
                      .uri("/api/audit/events")
                      .headers(reader.headers())
                      .retrieve()
                      .toBodilessEntity())
          .isInstanceOf(HttpClientErrorException.Forbidden.class)
          .satisfies(
              e ->
                  assertThat(((HttpClientErrorException) e).getResponseBodyAsString())
                      .contains("EMERGENCY_FREEZE"));
    } finally {
      owner.update("UPDATE emergency_flag SET enabled = FALSE WHERE id = 1");
      emergency.clearCache();
    }
    client.get().uri("/api/audit/events").headers(reader.headers()).retrieve().toBodilessEntity();
  }

  @Test
  void revocationTakesEffectWithoutCacheDelay() {
    TestAccount account = TestAccounts.create(owner, "doomed", Set.of("AUDIT_READER"));
    client.get().uri("/api/audit/events").headers(account.headers()).retrieve().toBodilessEntity();
    TestAccounts.revoke(owner, account.accountId());
    assertThatThrownBy(
            () ->
                client
                    .get()
                    .uri("/api/audit/events")
                    .headers(account.headers())
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
  }

  @Test
  @SuppressWarnings("unchecked")
  void trustCurrentIsPublicWithEmptyNotFound() {
    Map<String, Object> missing;
    try {
      missing =
          client.get().uri("/api/trust/snapshots/current").retrieve().body(Map.class);
    } catch (HttpClientErrorException.NotFound e) {
      assertThat(e.getResponseBodyAsString()).isEmpty();
      return;
    }
    assertThat(missing).containsKey("version");
  }
}
