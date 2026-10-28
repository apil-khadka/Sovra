package dev.sovra.verification;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.audit.AuditService;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.config.SovraMode;
import dev.sovra.consent.ConsentFixtures;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.issuance.StatusEvidenceFetcher;
import dev.sovra.issuance.TrustSnapshotProvider;
import dev.sovra.ops.TelemetryService;
import dev.sovra.tenancy.TenantContext;
import dev.sovra.tenancy.TenantDataSource;
import dev.sovra.trust.TrustService;
import dev.sovra.verification.VerificationFixtures.Stage;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Verification durability (FR-21, INV-01, INV-02, INV-07, INV-08):
 * one fresh acceptance per nonce across concurrent transactions and
 * across two service instances, byte-identical replays, UNKNOWN on
 * dependency outage, and atomic decision-plus-audit commits. Boots
 * as the least-privilege role, like production.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class VerificationFlowTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  @Autowired TrustService trust;

  @Autowired AuthorizationService authz;

  @Autowired AuditService audit;

  @Autowired TrustSnapshotProvider snapshots;

  @Autowired StatusEvidenceFetcher status;

  @Autowired DataSource dataSource;

  @Autowired PlatformTransactionManager transactions;

  @Autowired Clock clock;

  @Autowired ObjectMapper mapper;

  @Autowired TelemetryService telemetry;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() throws Exception {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
    IssuanceFixtures.ensureSyntheticIssuer(owner, trust, mapper);
  }

  private int decisionCount(String requestId) {
    Integer count = owner.queryForObject(
        "SELECT COUNT(*) FROM verification_decision WHERE request_id = ?",
        Integer.class, UUID.fromString(requestId));
    return count == null ? 0 : count;
  }

  @Test
  @SuppressWarnings("unchecked")
  void acceptFlowCommitsDecisionAndAuditAtomically() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "accept");
    String nonce = VerificationFixtures.nonce();
    Map<String, Object> body = VerificationFixtures.verifyBody(
        stage.holder(), stage.requestId(), nonce, ConsentFixtures.AUDIENCE, mapper);

    Map<String, Object> decided = VerificationFixtures.verify(client, stage.rp(), body);
    assertThat(decided).isNotNull();
    assertThat(decided.get("outcome")).isEqualTo("ACCEPTED");
    assertThat(decided.get("reasonCode")).isEqualTo("OK");
    assertThat(decided.get("synthetic")).isEqualTo(Boolean.TRUE);
    assertThat(decided.get("profile")).isEqualTo("sovra-g1-synthetic/0.2");
    assertThat(((Number) decided.get("trustSnapshot")).longValue()).isPositive();
    String decisionId = decided.get("decisionId").toString();

    // Decision and audit reference committed together: exactly one of
    // each, and no decision row lacks its audit row.
    assertThat(decisionCount(stage.requestId())).isEqualTo(1);
    Map<String, Object> audit =
        owner.queryForMap(
            "SELECT * FROM audit_event WHERE tenant_id = ? AND action = 'VERIFY_PRESENTATION'"
                + " AND decision = 'PERMIT' ORDER BY occurred_at DESC LIMIT 1",
            stage.rp().tenantId());
    assertThat(audit.get("detail").toString()).contains(decisionId);
    assertThat(audit.get("detail").toString()).contains("ACCEPTED");
    Integer orphans = owner.queryForObject(
        "SELECT COUNT(*) FROM verification_decision d WHERE NOT EXISTS"
            + " (SELECT 1 FROM audit_event a WHERE a.tenant_id = d.tenant_id"
            + " AND a.action = 'VERIFY_PRESENTATION'"
            + " AND a.detail::text LIKE '%' || d.id::text || '%')",
        Integer.class);
    assertThat(orphans).isZero();

    // Authorized retrieval returns the committed decision.
    Map<String, Object> retrieved =
        VerificationFixtures.decision(client, stage.rp(), decisionId);
    assertThat(retrieved.get("decisionId")).isEqualTo(decisionId);
    assertThat(retrieved.get("outcome")).isEqualTo("ACCEPTED");
    Map<String, Object> agentRead =
        VerificationFixtures.decision(client, stage.holderAgent(), decisionId);
    assertThat(agentRead.get("outcome")).isEqualTo("ACCEPTED");
  }

  @Test
  void replayAfterResponseLossReturnsByteIdenticalDecision() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "replay");
    String nonce = VerificationFixtures.nonce();
    Map<String, Object> body = VerificationFixtures.verifyBody(
        stage.holder(), stage.requestId(), nonce, ConsentFixtures.AUDIENCE, mapper);

    // The client "loses" the first response and retries identically.
    String first = VerificationFixtures.verifyRaw(client, stage.rp(), body);
    String second = VerificationFixtures.verifyRaw(client, stage.rp(), body);
    assertThat(second).isEqualTo(first);
    assertThat(decisionCount(stage.requestId())).isEqualTo(1);
    assertThat(mapper.readTree(first).get("outcome").asString()).isEqualTo("ACCEPTED");
  }

  @Test
  void concurrentSubmissionsCreateOneDecision() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "race");
    String nonce = VerificationFixtures.nonce();
    Map<String, Object> body = VerificationFixtures.verifyBody(
        stage.holder(), stage.requestId(), nonce, ConsentFixtures.AUDIENCE, mapper);

    int threads = 8;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    CountDownLatch gate = new CountDownLatch(1);
    try {
      List<Future<String>> futures = new ArrayList<>();
      for (int i = 0; i < threads; i++) {
        futures.add(pool.submit(() -> {
          gate.await(10, TimeUnit.SECONDS);
          return VerificationFixtures.verifyRaw(client, stage.rp(), body);
        }));
      }
      gate.countDown();
      List<String> responses = new ArrayList<>();
      for (Future<String> future : futures) {
        responses.add(future.get(60, TimeUnit.SECONDS));
      }
      // Every racer saw the same committed decision; the losers
      // reconciled against the winner's row.
      assertThat(responses).allSatisfy(response -> assertThat(response).isEqualTo(responses.get(0)));
      assertThat(mapper.readTree(responses.get(0)).get("outcome").asString())
          .isEqualTo("ACCEPTED");
    } finally {
      pool.shutdownNow();
    }
    assertThat(decisionCount(stage.requestId())).isEqualTo(1);
  }

  @Test
  void twoInstancesRacingOneNonceCommitOneDecision() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "two-inst");
    String nonce = VerificationFixtures.nonce();
    // Two service instances over separate tenant templates, as two app
    // instances would hold; enforcement lives in the database, not in
    // either process.
    VerificationService first = new VerificationService(authz, audit, snapshots, status,
        new JdbcTemplate(new TenantDataSource(dataSource)), clock, mapper, telemetry,
        "synthetic", new SovraMode("demo"));
    VerificationService second = new VerificationService(authz, audit, snapshots, status,
        new JdbcTemplate(new TenantDataSource(dataSource)), clock, mapper, telemetry,
        "synthetic", new SovraMode("demo"));
    ServiceAccountPrincipal principal = IssuanceFixtures.asPrincipal(stage.rp());
    JsonNode holderJwk = stage.holder().jwk();
    String binding = VerificationFixtures.bindingProof(
        stage.holder(), stage.requestId(), nonce, ConsentFixtures.AUDIENCE, mapper);
    VerificationService.VerifyRequest submission = new VerificationService.VerifyRequest(
        UUID.fromString(stage.requestId()), nonce, ConsentFixtures.AUDIENCE, holderJwk, binding);

    ExecutorService pool = Executors.newFixedThreadPool(2);
    CountDownLatch gate = new CountDownLatch(1);
    try {
      Future<String> won = pool.submit(() -> inTransaction(first, principal, submission, gate));
      Future<String> lost = pool.submit(() -> inTransaction(second, principal, submission, gate));
      gate.countDown();
      String a = won.get(60, TimeUnit.SECONDS);
      String b = lost.get(60, TimeUnit.SECONDS);
      // One winner, one reconciled loser: identical bytes, one row.
      assertThat(a).isEqualTo(b);
      assertThat(mapper.readTree(a).get("outcome").asString()).isEqualTo("ACCEPTED");
    } finally {
      pool.shutdownNow();
    }
    assertThat(decisionCount(stage.requestId())).isEqualTo(1);
  }

  private String inTransaction(
      VerificationService instance,
      ServiceAccountPrincipal principal,
      VerificationService.VerifyRequest submission,
      CountDownLatch gate) throws Exception {
    TransactionTemplate template = new TransactionTemplate(transactions);
    return template.execute(ignored -> {
      TenantContext.set(principal);
      try {
        gate.await(10, TimeUnit.SECONDS);
        return instance.verify(principal, submission);
      } catch (Exception e) {
        throw new IllegalStateException(e);
      } finally {
        TenantContext.clear();
      }
    });
  }

  @Test
  void trustOutageYieldsDurableUnknown() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "trust-out");
    String nonce = VerificationFixtures.nonce();
    // A snapshot provider that sees no governing snapshot, as during a
    // trust-dependency outage.
    TrustSnapshotProvider outage = Optional::empty;
    VerificationService instance = new VerificationService(authz, audit, outage, status,
        new JdbcTemplate(new TenantDataSource(dataSource)), clock, mapper, telemetry,
        "synthetic", new SovraMode("demo"));
    ServiceAccountPrincipal principal = IssuanceFixtures.asPrincipal(stage.rp());
    VerificationService.VerifyRequest submission = new VerificationService.VerifyRequest(
        UUID.fromString(stage.requestId()), nonce, ConsentFixtures.AUDIENCE,
        stage.holder().jwk(),
        VerificationFixtures.bindingProof(
            stage.holder(), stage.requestId(), nonce, ConsentFixtures.AUDIENCE, mapper));

    String response = new TransactionTemplate(transactions).execute(ignored -> {
      TenantContext.set(principal);
      try {
        return instance.verify(principal, submission);
      } finally {
        TenantContext.clear();
      }
    });
    assertThat(response).isNotNull();
    JsonNode decided = mapper.readTree(response);
    assertThat(decided.get("outcome").asString()).isEqualTo("UNKNOWN");
    assertThat(decided.get("reasonCode").asString()).isEqualTo("TRUST_UNAVAILABLE");
    assertThat(decided.get("trustSnapshot").asLong()).isZero();
    assertThat(decisionCount(stage.requestId())).isEqualTo(1);

    // UNKNOWN is stored evidence: authorized retrieval returns it, and
    // a fresh nonce may attempt again once trust recovers.
    Map<String, Object> retrieved = VerificationFixtures.decision(
        client, stage.rp(), decided.get("decisionId").asString());
    assertThat(retrieved.get("outcome")).isEqualTo("UNKNOWN");
    Map<String, Object> retry = VerificationFixtures.verify(client, stage.rp(),
        VerificationFixtures.verifyBody(stage.holder(), stage.requestId(),
            VerificationFixtures.nonce(), ConsentFixtures.AUDIENCE, mapper));
    assertThat(retry.get("outcome")).isEqualTo("ACCEPTED");
  }

  @Test
  void statusOutageYieldsUnknownNeverAccept() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "status-out");
    ServiceAccountPrincipal principal = IssuanceFixtures.asPrincipal(stage.rp());

    StatusEvidenceFetcher failing = credentialId -> {
      throw new IllegalStateException("status dependency is down");
    };
    String outage = verifyDirect(failing, principal, stage, VerificationFixtures.nonce());
    JsonNode decided = mapper.readTree(outage);
    assertThat(decided.get("outcome").asString()).isEqualTo("UNKNOWN");
    assertThat(decided.get("reasonCode").asString()).isEqualTo("STATUS_UNAVAILABLE");

    StatusEvidenceFetcher unknown = credentialId ->
        new StatusEvidenceFetcher.StatusEvidence(
            StatusEvidenceFetcher.Status.UNKNOWN, 0, clock.instant(),
            java.time.Duration.ofMinutes(15));
    String uncertain = verifyDirect(unknown, principal, stage, VerificationFixtures.nonce());
    JsonNode held = mapper.readTree(uncertain);
    assertThat(held.get("outcome").asString()).isEqualTo("UNKNOWN");
    assertThat(held.get("reasonCode").asString()).isEqualTo("STATUS_UNKNOWN");
    assertThat(decisionCount(stage.requestId())).isEqualTo(2);
  }

  private String verifyDirect(
      StatusEvidenceFetcher fetcher,
      ServiceAccountPrincipal principal,
      Stage stage,
      String nonce) throws Exception {
    VerificationService instance = new VerificationService(authz, audit, snapshots, fetcher,
        new JdbcTemplate(new TenantDataSource(dataSource)), clock, mapper, telemetry,
        "synthetic", new SovraMode("demo"));
    VerificationService.VerifyRequest submission = new VerificationService.VerifyRequest(
        UUID.fromString(stage.requestId()), nonce, ConsentFixtures.AUDIENCE,
        stage.holder().jwk(),
        VerificationFixtures.bindingProof(
            stage.holder(), stage.requestId(), nonce, ConsentFixtures.AUDIENCE, mapper));
    return new TransactionTemplate(transactions).execute(ignored -> {
      TenantContext.set(principal);
      try {
        return instance.verify(principal, submission);
      } finally {
        TenantContext.clear();
      }
    });
  }

  @Test
  void rejectedDecisionsReplayWithoutRewrite() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "rej-replay");
    owner.update("UPDATE proof_request SET expires_at = now() - INTERVAL '1 minute'"
        + " WHERE id = ?", UUID.fromString(stage.requestId()));

    String nonce = VerificationFixtures.nonce();
    Map<String, Object> body = VerificationFixtures.verifyBody(
        stage.holder(), stage.requestId(), nonce, ConsentFixtures.AUDIENCE, mapper);
    String first = VerificationFixtures.verifyRaw(client, stage.rp(), body);
    assertThat(mapper.readTree(first).get("outcome").asString()).isEqualTo("REJECTED");
    assertThat(mapper.readTree(first).get("reasonCode").asString()).isEqualTo("CONSENT_EXPIRED");
    // The rejection replays identically; it cannot become an acceptance.
    assertThat(VerificationFixtures.verifyRaw(client, stage.rp(), body)).isEqualTo(first);
    assertThat(decisionCount(stage.requestId())).isEqualTo(1);

    // A fresh nonce re-evaluates against current truth — still expired —
    // and records its own immutable rejection.
    Map<String, Object> retry = VerificationFixtures.verify(client, stage.rp(),
        VerificationFixtures.verifyBody(stage.holder(), stage.requestId(),
            VerificationFixtures.nonce(), ConsentFixtures.AUDIENCE, mapper));
    assertThat(retry.get("outcome")).isEqualTo("REJECTED");
    assertThat(decisionCount(stage.requestId())).isEqualTo(2);
  }

  @Test
  void uncommittedDecisionWorkNeverBecomesVisible() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "rollback");
    // A transaction that dies before commit — the process-kill shape —
    // must leave neither a decision nor a dangling row behind.
    java.sql.Connection connection = ownerDataSource().getConnection();
    try {
      connection.setAutoCommit(false);
      try (java.sql.PreparedStatement ps = connection.prepareStatement(
          "INSERT INTO verification_decision (tenant_id, request_id, credential_id, nonce,"
              + " request_hash, rp_id, audience, outcome, reason_code, response_body,"
              + " trust_snapshot_version, decided_by)"
              + " VALUES (?, ?, ?, ?, 'hash', 'rp', 'aud', 'ACCEPTED', 'OK', '{}', 1, 't')")) {
        ps.setObject(1, stage.rp().tenantId());
        ps.setObject(2, UUID.fromString(stage.requestId()));
        ps.setObject(3, UUID.fromString(stage.credentialId()));
        ps.setString(4, VerificationFixtures.nonce());
        ps.executeUpdate();
      }
      connection.rollback();
    } finally {
      connection.close();
    }
    assertThat(decisionCount(stage.requestId())).isZero();
  }

}
