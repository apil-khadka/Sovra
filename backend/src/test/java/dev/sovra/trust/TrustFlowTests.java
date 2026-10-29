package dev.sovra.trust;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraPostgresBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.auth.HumanMembershipRepository;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Role;
import dev.sovra.tenancy.TenantContext;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TrustFlowTests extends SovraPostgresBase {

  static final String VCT = "https://sovra.example/vct/adult-status/1";

  @LocalServerPort int port;

  @Autowired DataSource dataSource;

  @Autowired TrustService trust;

  @Autowired HumanMembershipRepository memberships;

  @Autowired ObjectMapper mapper;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
  }

  static Map<String, Object> issuer(String keyId) {
    return Map.of(
        "issuerId", "np-mock-issuer",
        "displayName", "Mock NP issuer",
        "scope", "adult-status",
        "credentialTypes", List.of(VCT),
        "keyId", keyId,
        "publicKeyJwk", p256Jwk(keyId),
        "validFrom", Instant.now().minusSeconds(60).toString(),
        "validThrough", Instant.now().plusSeconds(3600).toString(),
        "status", "ACTIVE");
  }

  static Map<String, Object> p256Jwk(String kid) {
    return Map.of(
        "kty", "EC",
        "crv", "P-256",
        "kid", kid,
        "x", "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y", "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
  }

  static Map<String, Object> policy() {
    return Map.of(
        "rpId", "demo-rp",
        "purpose", "age-gate",
        "allowedTypes", List.of(VCT),
        "maxAssurance", "MEDIUM");
  }

  static Map<String, Object> proposal() {
    return Map.of("issuers", List.of(issuer("key-1")), "policies", List.of(policy()), "note", "v1");
  }

  @Test
  void humanQuorumIsPersonVerified() {
    TestAccount anchor = TestAccounts.create(owner, "hq-anchor", Set.of("TENANT_MEMBER"));
    UUID tenant = anchor.tenantId();
    ServiceAccountPrincipal maker =
        memberships
            .upsert(
                tenant, "https://op.example/hq", "hq-maker", "HQ Maker",
                Set.of(Role.TRUST_ADMIN))
            .principal();
    ServiceAccountPrincipal checker =
        memberships
            .upsert(
                tenant, "https://op.example/hq", "hq-checker", "HQ Checker",
                Set.of(Role.TRUST_ADMIN))
            .principal();
    TrustService.ProposalInput input =
        new TrustService.ProposalInput(
            List.of(
                new TrustService.IssuerInput(
                    "np-mock-issuer", "Mock NP issuer", "adult-status", List.of(VCT),
                    "hq-1", 1, mapper.valueToTree(p256Jwk("hq-1")),
                    Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600),
                    "ACTIVE")),
            List.of(
                new TrustService.PolicyInput("demo-rp", "age-gate", List.of(VCT), "MEDIUM")));
    TenantContext.set(maker);
    try {
      TrustService.ProposalResult result = trust.propose(maker, input, "human quorum");
      assertThat(trust.approve(checker, result.proposalId())).isTrue();
    } finally {
      TenantContext.clear();
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void proposeApproveActivateFlow() {
    TestAccount maker = TestAccounts.create(owner, "maker", Set.of("TRUST_ADMIN"));
    TestAccount checker = TestAccounts.create(owner, "checker", Set.of("TRUST_ADMIN"));

    Map<String, Object> created =
        client
            .post()
            .uri("/api/trust/proposals")
            .headers(maker.headers())
            .body(proposal())
            .retrieve()
            .body(Map.class);
    assertThat(created).containsKeys("version", "proposalId");
    long version = Long.parseLong(created.get("version").toString());
    String proposalId = created.get("proposalId").toString();

    // Self-approval is forbidden.
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/trust/proposals/" + proposalId + "/approve")
                    .headers(maker.headers())
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Forbidden.class)
        .satisfies(
            e ->
                assertThat(((HttpClientErrorException) e).getResponseBodyAsString())
                    .contains("SELF_APPROVAL"));

    client
        .post()
        .uri("/api/trust/proposals/" + proposalId + "/approve")
        .headers(checker.headers())
        .retrieve()
        .toBodilessEntity();

    // Double approval conflicts.
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/trust/proposals/" + proposalId + "/approve")
                    .headers(checker.headers())
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Conflict.class);

    // Unknown proposal is an empty 404, not a leak.
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/trust/proposals/00000000-0000-0000-0000-000000000000/approve")
                    .headers(checker.headers())
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.NotFound.class)
        .satisfies(
            e -> assertThat(((HttpClientErrorException) e).getResponseBodyAsString()).isEmpty());

    client
        .post()
        .uri("/api/trust/snapshots/" + version + "/activate")
        .headers(checker.headers())
        .retrieve()
        .toBodilessEntity();

    Map<String, Object> current =
        client.get().uri("/api/trust/snapshots/current").retrieve().body(Map.class);
    assertThat(current).isNotNull();
    assertThat(Long.parseLong(current.get("version").toString())).isEqualTo(version);
    assertThat((List<?>) current.get("issuers")).hasSize(1);
    assertThat((List<?>) current.get("policies")).hasSize(1);
  }

  @Test
  @SuppressWarnings("unchecked")
  void activationOnlyMovesForward() {
    TestAccount maker = TestAccounts.create(owner, "fwd-maker", Set.of("TRUST_ADMIN"));
    TestAccount checker = TestAccounts.create(owner, "fwd-checker", Set.of("TRUST_ADMIN"));

    Map<String, Object> first =
        client
            .post()
            .uri("/api/trust/proposals")
            .headers(maker.headers())
            .body(proposal())
            .retrieve()
            .body(Map.class);
    long v1 = Long.parseLong(first.get("version").toString());
    client
        .post()
        .uri("/api/trust/proposals/" + first.get("proposalId") + "/approve")
        .headers(checker.headers())
        .retrieve()
        .toBodilessEntity();
    client
        .post()
        .uri("/api/trust/snapshots/" + v1 + "/activate")
        .headers(checker.headers())
        .retrieve()
        .toBodilessEntity();

    Map<String, Object> second =
        client
            .post()
            .uri("/api/trust/proposals")
            .headers(maker.headers())
            .body(Map.of("issuers", List.of(), "policies", List.of(policy()), "note", "v2"))
            .retrieve()
            .body(Map.class);
    long v2 = Long.parseLong(second.get("version").toString());
    assertThat(v2).isGreaterThan(v1);
    client
        .post()
        .uri("/api/trust/proposals/" + second.get("proposalId") + "/approve")
        .headers(checker.headers())
        .retrieve()
        .toBodilessEntity();
    client
        .post()
        .uri("/api/trust/snapshots/" + v2 + "/activate")
        .headers(checker.headers())
        .retrieve()
        .toBodilessEntity();

    // Rolling back to the older version is rejected.
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/trust/snapshots/" + v1 + "/activate")
                    .headers(checker.headers())
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.BadRequest.class);

    Map<String, Object> current =
        client.get().uri("/api/trust/snapshots/current").retrieve().body(Map.class);
    assertThat(Long.parseLong(current.get("version").toString())).isEqualTo(v2);
  }

  @Test
  void activationWithoutApprovalIsRejected() {
    TestAccount maker = TestAccounts.create(owner, "noapr-maker", Set.of("TRUST_ADMIN"));
    Map<String, Object> created =
        client
            .post()
            .uri("/api/trust/proposals")
            .headers(maker.headers())
            .body(proposal())
            .retrieve()
            .body(Map.class);
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/trust/snapshots/" + created.get("version") + "/activate")
                    .headers(maker.headers())
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }
}
