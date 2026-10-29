package dev.sovra.trust;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraPostgresBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TrustNegativeTests extends SovraPostgresBase {

  @LocalServerPort int port;

  @Autowired DataSource dataSource;

  RestClient client;
  JdbcTemplate owner;
  TestAccount admin;

  @BeforeEach
  void setup() {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
    admin = TestAccounts.create(owner, "neg-admin", Set.of("TRUST_ADMIN"));
  }

  private Map<String, Object> issuerWith(Map<String, Object> jwk, String vct) {
    Map<String, Object> issuer = new HashMap<>(TrustFlowTests.issuer("key-neg"));
    issuer.put("publicKeyJwk", jwk);
    issuer.put("credentialTypes", List.of(vct));
    return issuer;
  }

  private void assertBad(Map<String, Object> body) {
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/trust/proposals")
                    .headers(admin.headers())
                    .body(body)
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void unapprovedCredentialTypeIsRejected() {
    assertBad(
        Map.of(
            "issuers",
            List.of(issuerWith(TrustFlowTests.p256Jwk("key-neg"), "https://evil.example/vct/x")),
            "policies",
            List.of()));
  }

  @Test
  void rsaKeyIsRejected() {
    Map<String, Object> rsa = new HashMap<>(TrustFlowTests.p256Jwk("key-neg"));
    rsa.put("kty", "RSA");
    rsa.put("n", "x");
    rsa.put("e", "AQAB");
    assertBad(
        Map.of(
            "issuers",
            List.of(issuerWith(rsa, TrustFlowTests.VCT)),
            "policies",
            List.of()));
  }

  @Test
  void privateKeyMaterialIsRejected() {
    Map<String, Object> withD = new HashMap<>(TrustFlowTests.p256Jwk("key-neg"));
    withD.put("d", "CANARY-PRIVATE");
    assertBad(
        Map.of(
            "issuers",
            List.of(issuerWith(withD, TrustFlowTests.VCT)),
            "policies",
            List.of()));
  }

  @Test
  void kidMismatchIsRejected() {
    assertBad(
        Map.of(
            "issuers",
            List.of(issuerWith(TrustFlowTests.p256Jwk("other-kid"), TrustFlowTests.VCT)),
            "policies",
            List.of()));
  }

  @Test
  void expiredKeyIsRejected() {
    Map<String, Object> issuer = new HashMap<>(TrustFlowTests.issuer("key-neg"));
    issuer.put("validFrom", Instant.now().minusSeconds(7200).toString());
    issuer.put("validThrough", Instant.now().minusSeconds(3600).toString());
    assertBad(Map.of("issuers", List.of(issuer), "policies", List.of()));
  }

  @Test
  void emptyProposalIsRejected() {
    assertBad(Map.of("issuers", List.of(), "policies", List.of()));
  }

  @Test
  void unknownAssuranceIsRejected() {
    Map<String, Object> policy = new HashMap<>(TrustFlowTests.policy());
    policy.put("maxAssurance", "ULTRA");
    assertBad(Map.of("issuers", List.of(), "policies", List.of(policy)));
  }

  @Test
  void memberCannotPropose() {
    TestAccount member = TestAccounts.create(owner, "neg-member", Set.of("TENANT_MEMBER"));
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/trust/proposals")
                    .headers(member.headers())
                    .body(Map.of("issuers", List.of(), "policies", List.of(TrustFlowTests.policy())))
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
  }

  @Test
  void databaseTriggerRejectsSelfApproval() {
    TestAccount maker = TestAccounts.create(owner, "trig-maker", Set.of("TRUST_ADMIN"));
    Long version =
        owner.queryForObject(
            "INSERT INTO trust_snapshot (created_by) VALUES ('trig') RETURNING version", Long.class);
    var proposalId = java.util.UUID.randomUUID();
    owner.update(
        "INSERT INTO trust_change_proposal (id, snapshot_version, proposed_by, proposed_by_account)"
            + " VALUES (?, ?, ?, ?)",
        proposalId,
        version,
        maker.name(),
        maker.accountId());
    // Same account UUID: rejected even though the label differs, because
    // the trigger compares identity, never names.
    assertThatThrownBy(
            () ->
                owner.update(
                    "INSERT INTO trust_proposal_decision"
                        + " (proposal_id, approved_by, approved_by_account) VALUES (?, ?, ?)",
                    proposalId,
                    "a-different-label",
                    maker.accountId()))
        .hasMessageContaining("self-approval");
    // NULL identities (migration-seed shape) stay permitted: the sealed
    // function, not the trigger, requires identity for new runtime rows.
    Long seedVersion =
        owner.queryForObject(
            "INSERT INTO trust_snapshot (created_by) VALUES ('seed') RETURNING version", Long.class);
    var seedProposal = java.util.UUID.randomUUID();
    owner.update(
        "INSERT INTO trust_change_proposal (id, snapshot_version, proposed_by) VALUES (?, ?, ?)",
        seedProposal,
        seedVersion,
        "seed");
    owner.update(
        "INSERT INTO trust_proposal_decision (proposal_id, approved_by) VALUES (?, ?)",
        seedProposal,
        "seed");
  }
}
