package dev.sovra.trust;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

/**
 * Seal proofs (SOV-040, SR-35, MC-09): the runtime role writes trust
 * state only through the sealed functions, activated versions are
 * immutable even for the owner, approval identity is the account UUID,
 * and denials survive as audit evidence.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TrustSealTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  @Autowired DataSource dataSource;

  RestClient client;
  JdbcTemplate owner;
  JdbcTemplate app;

  @BeforeEach
  void setup() {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
    app = new JdbcTemplate(dataSource);
  }

  @Test
  void appRoleCannotWriteTrustTablesDirectly() {
    String[] writes = {
      "INSERT INTO trust_snapshot (created_by) VALUES ('forged')",
      "INSERT INTO trust_snapshot_activation (snapshot_version, activated_by) VALUES (1, 'forged')",
      "INSERT INTO issuer_record (snapshot_version, issuer_id) VALUES (1, 'forged')",
      "INSERT INTO rp_policy (snapshot_version, rp_id) VALUES (1, 'forged')",
      "INSERT INTO trust_change_proposal (snapshot_version, proposed_by) VALUES (1, 'forged')",
      "INSERT INTO trust_proposal_decision (proposal_id, approved_by)"
          + " VALUES (gen_random_uuid(), 'forged')",
      "UPDATE trust_snapshot SET note = 'forged' WHERE version = 1",
      "DELETE FROM trust_snapshot_activation WHERE snapshot_version = 1",
      "SELECT nextval('trust_snapshot_version_seq')"
    };
    for (String sql : writes) {
      // Spring's translated message drops the server detail, so the
      // denial is asserted on the full trace (PostgreSQL 42501).
      assertThatThrownBy(() -> app.execute(sql))
          .as("runtime write must fail: " + sql)
          .isInstanceOf(DataAccessException.class)
          .hasStackTraceContaining("permission denied");
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void sealedFlowRecordsUuidIdentity() {
    TestAccount maker = TestAccounts.create(owner, "seal-maker", Set.of("TRUST_ADMIN"));
    TestAccount checker = TestAccounts.create(owner, "seal-checker", Set.of("TRUST_ADMIN"));
    Map<String, Object> created =
        client
            .post()
            .uri("/api/trust/proposals")
            .headers(maker.headers())
            .body(TrustFlowTests.proposal())
            .retrieve()
            .body(Map.class);
    assertThat(created).isNotNull();
    String proposalId = created.get("proposalId").toString();
    long version = Long.parseLong(created.get("version").toString());
    Map<?, ?> approval =
        client
            .post()
            .uri("/api/trust/proposals/" + proposalId + "/approve")
            .headers(checker.headers())
            .retrieve()
            .body(Map.class);
    assertThat(approval.get("personVerified")).isEqualTo("false");
    client
        .post()
        .uri("/api/trust/snapshots/" + version + "/activate")
        .headers(checker.headers())
        .retrieve()
        .toBodilessEntity();

    assertThat(
            owner.queryForObject(
                "SELECT proposed_by_account FROM trust_change_proposal WHERE id = ?",
                UUID.class,
                UUID.fromString(proposalId)))
        .isEqualTo(maker.accountId());
    Map<String, Object> decision =
        owner.queryForMap(
            "SELECT approved_by_account, approved_by, person_verified"
                + " FROM trust_proposal_decision WHERE proposal_id = ?",
            UUID.fromString(proposalId));
    assertThat(decision.get("approved_by_account")).isEqualTo(checker.accountId());
    assertThat(decision.get("approved_by")).isEqualTo(checker.name());
    assertThat(decision.get("person_verified")).isEqualTo(Boolean.FALSE);
    assertThat(
            owner.queryForObject(
                "SELECT activated_by_account FROM trust_snapshot_activation"
                    + " WHERE snapshot_version = ?",
                UUID.class,
                version))
        .isEqualTo(checker.accountId());
  }

  @Test
  void lateAppendToActiveVersionRejectedEvenForOwner() {
    Long active =
        owner.queryForObject(
            "SELECT MAX(snapshot_version) FROM trust_snapshot_activation", Long.class);
    assertThat(active).isNotNull();
    assertThatThrownBy(
            () ->
                owner.update(
                    "INSERT INTO issuer_record (snapshot_version, issuer_id, display_name, scope,"
                        + " credential_types, key_id, key_version, public_key_jwk, valid_from,"
                        + " valid_through, status) VALUES (?, 'late', 'Late', 'x', '{}', 'k', 1,"
                        + " '{}', now(), now(), 'ACTIVE')",
                    active))
        .isInstanceOf(DataAccessException.class)
        .hasMessageContaining("is sealed");
    assertThatThrownBy(
            () ->
                owner.update(
                    "INSERT INTO rp_policy (snapshot_version, rp_id, purpose, allowed_types,"
                        + " max_assurance) VALUES (?, 'late', 'x', '{}', 'LOW')",
                    active))
        .isInstanceOf(DataAccessException.class)
        .hasMessageContaining("is sealed");
  }

  @Test
  void activationWithoutApprovalRejected() {
    Long version =
        owner.queryForObject(
            "INSERT INTO trust_snapshot (created_by, note) VALUES ('seal-test', '')"
                + " RETURNING version",
            Long.class);
    assertThatThrownBy(
            () ->
                owner.update(
                    "INSERT INTO trust_snapshot_activation (snapshot_version, activated_by)"
                        + " VALUES (?, 'seal-test')",
                    version))
        .isInstanceOf(DataAccessException.class)
        .hasMessageContaining("no approved proposal");
  }

  @Test
  void backwardActivationRejected() {
    Long active =
        owner.queryForObject(
            "SELECT MAX(snapshot_version) FROM trust_snapshot_activation", Long.class);
    assertThat(active).isNotNull();
    // The current (or any older) version never moves forward: even the
    // owner cannot re-activate what is already the tip.
    assertThatThrownBy(
            () ->
                owner.update(
                    "INSERT INTO trust_snapshot_activation (snapshot_version, activated_by)"
                        + " VALUES (?, 'seal-test')",
                    active))
        .isInstanceOf(DataAccessException.class)
        .hasMessageContaining("does not move forward");
  }

  @Test
  @SuppressWarnings("unchecked")
  void sameNameDifferentAccountsAreDistinctMakers() {
    // Display names are labels only: two accounts sharing one name are
    // still two identities, and the quorum compares UUIDs.
    TestAccount maker = TestAccounts.create(owner, "shared-name", Set.of("TRUST_ADMIN"));
    TestAccount checker = TestAccounts.create(owner, "shared-name", Set.of("TRUST_ADMIN"));
    assertThat(checker.accountId()).isNotEqualTo(maker.accountId());
    Map<String, Object> created =
        client
            .post()
            .uri("/api/trust/proposals")
            .headers(maker.headers())
            .body(TrustFlowTests.proposal())
            .retrieve()
            .body(Map.class);
    assertThat(created).isNotNull();
    client
        .post()
        .uri("/api/trust/proposals/" + created.get("proposalId") + "/approve")
        .headers(checker.headers())
        .retrieve()
        .toBodilessEntity();
    assertThat(
            owner.queryForObject(
                "SELECT approved_by_account FROM trust_proposal_decision WHERE proposal_id = ?",
                UUID.class,
                UUID.fromString(created.get("proposalId").toString())))
        .isEqualTo(checker.accountId());
  }

  @Test
  @SuppressWarnings("unchecked")
  void selfApprovalDenialSurvivesAsAuditEvidence() {
    TestAccount maker = TestAccounts.create(owner, "seal-self", Set.of("TRUST_ADMIN"));
    Map<String, Object> created =
        client
            .post()
            .uri("/api/trust/proposals")
            .headers(maker.headers())
            .body(TrustFlowTests.proposal())
            .retrieve()
            .body(Map.class);
    assertThat(created).isNotNull();
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/trust/proposals/" + created.get("proposalId") + "/approve")
                    .headers(maker.headers())
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    Map<String, Object> denial =
        owner.queryForMap(
            "SELECT decision, reason_code FROM audit_event"
                + " WHERE tenant_id IS NULL AND action = 'APPROVE_TRUST_CHANGE'"
                + " AND resource_id = ? ORDER BY occurred_at DESC LIMIT 1",
            created.get("proposalId").toString());
    assertThat(denial.get("decision")).isEqualTo("DENY");
    assertThat(denial.get("reason_code")).isEqualTo("SELF_APPROVAL");
  }

  @Test
  void functionRefusesSamePersonQuorum() {
    // Two UUID-distinct rows bound to one OIDC subject are one person:
    // the function refuses, and records person_verified only for two
    // distinct subjects.
    owner.update("INSERT INTO trust_snapshot (created_by, note) VALUES ('seal-test', '')");
    UUID one =
        owner.queryForObject(
            "INSERT INTO trust_change_proposal"
                + " (snapshot_version, proposed_by, proposed_by_account, proposed_by_subject)"
                + " VALUES ((SELECT MAX(version) FROM trust_snapshot), 'm1',"
                + " gen_random_uuid(), 'sub-same') RETURNING id",
            UUID.class);
    assertThat(one).isNotNull();
    assertThatThrownBy(
            () ->
                owner.queryForObject(
                    "SELECT trust_approve(?, gen_random_uuid(), 'c1', 'sub-same', NULL)",
                    Boolean.class,
                    one))
        .hasMessageContaining("one person identity");

    Long tip =
        owner.queryForObject(
            "INSERT INTO trust_snapshot (created_by, note) VALUES ('seal-test', '')"
                + " RETURNING version",
            Long.class);
    UUID two =
        owner.queryForObject(
            "INSERT INTO trust_change_proposal"
                + " (snapshot_version, proposed_by, proposed_by_account, proposed_by_subject)"
                + " VALUES (?, 'm2', gen_random_uuid(), 'sub-a') RETURNING id",
            UUID.class,
            tip);
    Boolean verified =
        owner.queryForObject(
            "SELECT trust_approve(?, gen_random_uuid(), 'c2', 'sub-b', NULL)", Boolean.class, two);
    assertThat(verified).isTrue();
    assertThat(
            owner.queryForObject(
                "SELECT person_verified FROM trust_proposal_decision WHERE proposal_id = ?",
                Boolean.class,
                two))
        .isTrue();
  }

  @Test
  void functionRefusesSelfApprovalAndUnknownProposals() {
    UUID missing = UUID.randomUUID();
    assertThatThrownBy(
            () ->
                owner.queryForObject(
                    "SELECT trust_approve(?, gen_random_uuid(), 'c', NULL, NULL)", Boolean.class,
                    missing))
        .hasMessageContaining("unknown proposal");
    UUID account = UUID.randomUUID();
    Long tip =
        owner.queryForObject(
            "INSERT INTO trust_snapshot (created_by, note) VALUES ('seal-test', '')"
                + " RETURNING version",
            Long.class);
    UUID proposal =
        owner.queryForObject(
            "INSERT INTO trust_change_proposal"
                + " (snapshot_version, proposed_by, proposed_by_account)"
                + " VALUES (?, 'm', ?) RETURNING id",
            UUID.class,
            tip,
            account);
    assertThatThrownBy(
            () ->
                owner.queryForObject(
                    "SELECT trust_approve(?, ?, 'm', NULL, NULL)", Boolean.class, proposal,
                    account))
        .hasMessageContaining("self-approval");
  }

  @Test
  void doubleApprovalConflicts() {
    Long tip =
        owner.queryForObject(
            "INSERT INTO trust_snapshot (created_by, note) VALUES ('seal-test', '')"
                + " RETURNING version",
            Long.class);
    UUID proposal =
        owner.queryForObject(
            "INSERT INTO trust_change_proposal"
                + " (snapshot_version, proposed_by, proposed_by_account)"
                + " VALUES (?, 'm', gen_random_uuid()) RETURNING id",
            UUID.class,
            tip);
    Boolean first =
        owner.queryForObject(
            "SELECT trust_approve(?, gen_random_uuid(), 'c1', NULL, NULL)", Boolean.class,
            proposal);
    assertThat(first).isFalse();
    assertThatThrownBy(
            () ->
                owner.queryForObject(
                    "SELECT trust_approve(?, gen_random_uuid(), 'c2', NULL, NULL)", Boolean.class,
                    proposal))
        .hasMessageContaining("already decided");
  }
}
