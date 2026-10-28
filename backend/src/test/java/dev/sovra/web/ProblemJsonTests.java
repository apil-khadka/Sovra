package dev.sovra.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.issuance.IssuanceFixtures.HolderKeys;
import dev.sovra.trust.TrustService;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * RFC 9457 negotiation (SOV-015, IF-10, IF-07): the default bodies stay
 * the frozen legacy contract, while {@code Accept:
 * application/problem+json} yields typed problem details with Sovra
 * code/correlation/retryable extensions. 404s stay empty in both.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ProblemJsonTests extends SovraAppRoleBase {

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

  @SuppressWarnings("unchecked")
  private Map<String, Object> problem(HttpClientErrorException e) {
    try {
      return mapper.readValue(e.getResponseBodyAsString(), Map.class);
    } catch (Exception ex) {
      throw new IllegalStateException("problem body is not JSON", ex);
    }
  }

  @Test
  void legacyBodiesStayByteIdenticalByDefault() {
    TestAccount member = TestAccounts.create(owner, "problem-legacy", Set.of("TENANT_MEMBER"));
    assertThatThrownBy(
            () ->
                client
                    .get()
                    .uri("/api/issuance/credentials/not-a-uuid")
                    .headers(member.headers())
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOfSatisfying(
            HttpClientErrorException.BadRequest.class,
            e -> assertThat(e.getResponseBodyAsString()).contains("invalid_request"));
  }

  @Test
  void invalidRequestMapsToProblemDetails() {
    TestAccount member = TestAccounts.create(owner, "problem-400", Set.of("TENANT_MEMBER"));
    assertThatThrownBy(
            () ->
                client
                    .get()
                    .uri("/api/issuance/credentials/not-a-uuid")
                    .headers(member.headers())
                    .accept(MediaType.parseMediaType("application/problem+json"))
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOfSatisfying(
            HttpClientErrorException.BadRequest.class,
            e -> {
              assertThat(e.getResponseHeaders().getContentType().toString())
                  .contains("application/problem+json");
              Map<String, Object> body = problem(e);
              assertThat(body.get("code")).isEqualTo("invalid_request");
              assertThat(body.get("status")).isEqualTo(400);
              assertThat(body.get("retryable")).isEqualTo(Boolean.FALSE);
              assertThat(body.get("correlationId").toString()).isNotBlank();
            });
  }

  @Test
  void forbiddenCarriesOnlyTheReasonCode() {
    TestAccount member = TestAccounts.create(owner, "problem-403", Set.of("TENANT_MEMBER"));
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/trust/proposals")
                    .headers(member.headers())
                    .accept(MediaType.parseMediaType("application/problem+json"))
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{}")
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOfSatisfying(
            HttpClientErrorException.Forbidden.class,
            e -> {
              Map<String, Object> body = problem(e);
              assertThat(body.get("code")).isEqualTo("forbidden:MISSING_ROLE");
              assertThat(body.get("retryable")).isEqualTo(Boolean.FALSE);
              assertThat(e.getResponseBodyAsString()).doesNotContain("token", "secret");
            });
  }

  @Test
  void notFoundStaysEmptyEvenForProblemClients() {
    TestAccount member = TestAccounts.create(owner, "problem-404", Set.of("TENANT_MEMBER"));
    assertThatThrownBy(
            () ->
                client
                    .get()
                    .uri("/api/issuance/credentials/" + UUID.randomUUID())
                    .headers(member.headers())
                    .accept(MediaType.parseMediaType("application/problem+json"))
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOfSatisfying(
            HttpClientErrorException.NotFound.class,
            e -> assertThat(e.getResponseBodyAsString()).isNullOrEmpty());
  }

  @Test
  void alreadyDecidedMapsToConflictProblem() {
    TestAccount maker = TestAccounts.create(owner, "problem-maker", Set.of("TRUST_ADMIN"));
    TestAccount checker =
        TestAccounts.createInTenant(owner, maker.tenantId(), "problem-checker", Set.of("TRUST_ADMIN"));
    Map<String, Object> proposal =
        Map.of(
            "issuers",
            List.of(
                Map.of(
                    "issuerId", "np-mock-issuer",
                    "displayName", "Mock NP issuer",
                    "scope", "adult-status",
                    "credentialTypes", List.of(IssuanceFixtures.ADULT_VCT),
                    "keyId", "key-1",
                    "publicKeyJwk", Map.of(
                        "kty", "EC",
                        "crv", "P-256",
                        "kid", "key-1",
                        "x", "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                        "y", "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"),
                    "validFrom", Instant.now().minusSeconds(60).toString(),
                    "validThrough", Instant.now().plusSeconds(3600).toString(),
                    "status", "ACTIVE")),
            "policies",
            List.of(
                Map.of(
                    "rpId", "demo-rp",
                    "purpose", "age-gate",
                    "allowedTypes", List.of(IssuanceFixtures.ADULT_VCT),
                    "maxAssurance", "MEDIUM")));
    @SuppressWarnings("unchecked")
    Map<String, Object> created =
        client
            .post()
            .uri("/api/trust/proposals")
            .headers(maker.headers())
            .contentType(MediaType.APPLICATION_JSON)
            .body(proposal)
            .retrieve()
            .body(Map.class);
    assertThat(created).isNotNull();
    String proposalId = created.get("proposalId").toString();
    client
        .post()
        .uri("/api/trust/proposals/" + proposalId + "/approve")
        .headers(checker.headers())
        .retrieve()
        .toBodilessEntity();

    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/trust/proposals/" + proposalId + "/approve")
                    .headers(checker.headers())
                    .accept(MediaType.parseMediaType("application/problem+json"))
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOfSatisfying(
            HttpClientErrorException.Conflict.class,
            e -> {
              assertThat(problem(e).get("code")).isEqualTo("already_decided");
              assertThat(problem(e).get("retryable")).isEqualTo(Boolean.FALSE);
            });
  }

  @Test
  void idempotencyConflictMapsToUnprocessableProblem() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "problem-issuer", Set.of("ISSUER_OPS"));
    HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String key = "problem-" + UUID.randomUUID();
    Map<String, Object> first = issuanceBody(holder, key, Instant.now().plusSeconds(7200));
    client
        .post()
        .uri("/api/issuance/credentials")
        .headers(
            h -> {
              issuer.headers().accept(h);
              h.set("Idempotency-Key", key);
            })
        .contentType(MediaType.APPLICATION_JSON)
        .body(first)
        .retrieve()
        .toBodilessEntity();

    Map<String, Object> second = issuanceBody(holder, key, Instant.now().plusSeconds(3600));
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/issuance/credentials")
                    .headers(
                        h -> {
                          issuer.headers().accept(h);
                          h.set("Idempotency-Key", key);
                        })
                    .accept(MediaType.parseMediaType("application/problem+json"))
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(second)
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOfSatisfying(
            HttpClientErrorException.UnprocessableContent.class,
            e -> {
              assertThat(e.getStatusCode()).isEqualTo(HttpStatusCode.valueOf(422));
              assertThat(problem(e).get("code")).isEqualTo("idempotency_conflict");
              assertThat(problem(e).get("retryable")).isEqualTo(Boolean.FALSE);
            });
  }

  private Map<String, Object> issuanceBody(HolderKeys holder, String key, Instant expiresAt)
      throws Exception {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("issuerId", IssuanceFixtures.ISSUER_ID);
    body.put("vct", IssuanceFixtures.ADULT_VCT);
    body.put("holderJwk", mapper.convertValue(holder.jwk(), Map.class));
    body.put("holderProof", IssuanceFixtures.proof(holder, key, IssuanceFixtures.ADULT_VCT, mapper));
    body.put("claims", Map.of("adultOver18", Boolean.TRUE));
    body.put("expiresAt", expiresAt.toString());
    return body;
  }
}
