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
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
 * Status freshness and dependency-outage containment (SOV-012, FR-30,
 * SR-06, INV-04): stale evidence never decides, provider throwables
 * record UNKNOWN, every decision carries its actual authority/key/status
 * versions, and current denials win even when positive caches are warm.
 * Boots as the least-privilege role, like production.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class VerificationFreshnessTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  @Autowired TrustService trust;

  @Autowired AuthorizationService authz;

  @Autowired AuditService audit;

  @Autowired TrustSnapshotProvider snapshots;

  @Autowired DataSource dataSource;

  @Autowired PlatformTransactionManager transactions;

  @Autowired Clock clock;

  @Autowired TelemetryService telemetry;

  @Autowired ObjectMapper mapper;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() throws Exception {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
    IssuanceFixtures.ensureSyntheticIssuer(owner, trust, mapper);
  }

  private String verifyDirect(
      TrustSnapshotProvider provider,
      StatusEvidenceFetcher fetcher,
      ServiceAccountPrincipal principal,
      Stage stage,
      String nonce) throws Exception {
    VerificationService instance = new VerificationService(authz, audit, provider, fetcher,
        new JdbcTemplate(new TenantDataSource(dataSource)), clock, mapper, telemetry,
        "synthetic", new SovraMode("demo"));
    String binding = VerificationFixtures.bindingProof(
        stage.holder(), stage.requestId(), nonce, ConsentFixtures.AUDIENCE, mapper);
    VerificationService.VerifyRequest submission = new VerificationService.VerifyRequest(
        UUID.fromString(stage.requestId()), nonce, ConsentFixtures.AUDIENCE,
        stage.holder().jwk(), binding);
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
  void staleStatusEvidenceYieldsUnknownWithItsVersion() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "stale");
    ServiceAccountPrincipal principal = IssuanceFixtures.asPrincipal(stage.rp());
    // A VALID verdict older than its declared 15-minute bound: recorded
    // with its version, but never trusted for a decision.
    StatusEvidenceFetcher stale = credentialId ->
        new StatusEvidenceFetcher.StatusEvidence(
            StatusEvidenceFetcher.Status.VALID, 7,
            clock.instant().minus(Duration.ofMinutes(16)), Duration.ofMinutes(15));
    String response =
        verifyDirect(snapshots, stale, principal, stage, VerificationFixtures.nonce());
    JsonNode decided = mapper.readTree(response);
    assertThat(decided.get("outcome").asString()).isEqualTo("UNKNOWN");
    assertThat(decided.get("reasonCode").asString()).isEqualTo("STATUS_STALE");
    assertThat(decided.get("statusVersion").asLong()).isEqualTo(7);
    assertThat(decided.get("trustSnapshot").asLong()).isZero();

    Map<String, Object> retrieved = VerificationFixtures.decision(
        client, stage.rp(), decided.get("decisionId").asString());
    assertThat(retrieved.get("outcome")).isEqualTo("UNKNOWN");
    assertThat(((Number) retrieved.get("statusVersion")).longValue()).isEqualTo(7);
  }

  @Test
  void trustThrowerYieldsUnknownNeverAccept() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "trust-throw");
    ServiceAccountPrincipal principal = IssuanceFixtures.asPrincipal(stage.rp());
    StatusEvidenceFetcher live = credentialId ->
        new StatusEvidenceFetcher.StatusEvidence(
            StatusEvidenceFetcher.Status.VALID, 3, clock.instant(), Duration.ofMinutes(15));
    TrustSnapshotProvider throwing = () -> {
      throw new IllegalStateException("trust dependency is down");
    };
    String response =
        verifyDirect(throwing, live, principal, stage, VerificationFixtures.nonce());
    JsonNode decided = mapper.readTree(response);
    assertThat(decided.get("outcome").asString()).isEqualTo("UNKNOWN");
    assertThat(decided.get("reasonCode").asString()).isEqualTo("TRUST_UNAVAILABLE");
    // The consulted status version is still recorded.
    assertThat(decided.get("statusVersion").asLong()).isEqualTo(3);
  }

  @Test
  void statusThrowerRecordsUnknownWithoutVersions() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "status-throw");
    ServiceAccountPrincipal principal = IssuanceFixtures.asPrincipal(stage.rp());
    StatusEvidenceFetcher failing = credentialId -> {
      throw new IllegalStateException("status dependency is down");
    };
    String response =
        verifyDirect(snapshots, failing, principal, stage, VerificationFixtures.nonce());
    JsonNode decided = mapper.readTree(response);
    assertThat(decided.get("outcome").asString()).isEqualTo("UNKNOWN");
    assertThat(decided.get("reasonCode").asString()).isEqualTo("STATUS_UNAVAILABLE");
    assertThat(decided.get("trustSnapshot").asLong()).isZero();
    assertThat(decided.get("keyRef").asString()).isEmpty();
    assertThat(decided.get("statusVersion").asLong()).isZero();
  }

  @Test
  @SuppressWarnings("unchecked")
  void currentDenialWinsOverWarmCachesWithExactVersions() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "warm-deny");
    // Warm every positive cache: permission, trust snapshot, status.
    Map<String, Object> accepted =
        VerificationFixtures.verify(client, stage.rp(),
            VerificationFixtures.verifyBody(stage.holder(), stage.requestId(),
                VerificationFixtures.nonce(), ConsentFixtures.AUDIENCE, mapper));
    assertThat(accepted.get("outcome")).isEqualTo("ACCEPTED");
    assertThat(((Number) accepted.get("trustSnapshot")).longValue()).isPositive();
    assertThat(accepted.get("keyRef"))
        .isEqualTo(IssuanceFixtures.ISSUER_ID + ":synth-1:v1");
    assertThat(((Number) accepted.get("statusVersion")).longValue()).isEqualTo(1);

    // Terminal revocation bumps the status version to 2.
    Map<String, Object> revoked =
        client.post().uri("/api/issuance/credentials/" + stage.credentialId() + "/revoke")
            .headers(stage.issuer().headers()).retrieve().body(Map.class);
    assertThat(revoked).isNotNull();
    assertThat(revoked.get("status")).isEqualTo("REVOKED");
    Map<String, Object> status =
        client.get().uri("/api/issuance/credentials/" + stage.credentialId() + "/status")
            .headers(stage.issuer().headers()).retrieve().body(Map.class);
    assertThat(status).isNotNull();
    assertThat(status.get("status")).isEqualTo("REVOKED");
    assertThat(((Number) status.get("version")).longValue()).isEqualTo(2);

    // Despite the warm caches, the fresh attempt is rejected with the
    // current denial and its exact versions.
    Map<String, Object> denied =
        VerificationFixtures.verify(client, stage.rp(),
            VerificationFixtures.verifyBody(stage.holder(), stage.requestId(),
                VerificationFixtures.nonce(), ConsentFixtures.AUDIENCE, mapper));
    assertThat(denied.get("outcome")).isEqualTo("REJECTED");
    assertThat(denied.get("reasonCode")).isEqualTo("CREDENTIAL_REVOKED");
    assertThat(((Number) denied.get("statusVersion")).longValue()).isEqualTo(2);
    Map<String, Object> stored =
        VerificationFixtures.decision(client, stage.rp(), denied.get("decisionId").toString());
    assertThat(stored.get("reasonCode")).isEqualTo("CREDENTIAL_REVOKED");
    assertThat(((Number) stored.get("statusVersion")).longValue()).isEqualTo(2);
  }

  @Test
  @SuppressWarnings("unchecked")
  void concurrentRevokesConvergeOnOneVersionBump() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "rev-race");
    int threads = 8;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    CountDownLatch gate = new CountDownLatch(1);
    try {
      List<Future<Map<String, Object>>> futures = new ArrayList<>();
      for (int i = 0; i < threads; i++) {
        futures.add(
            pool.submit(
                () -> {
                  gate.await(10, TimeUnit.SECONDS);
                  return client.post()
                      .uri("/api/issuance/credentials/" + stage.credentialId() + "/revoke")
                      .headers(stage.issuer().headers())
                      .retrieve()
                      .body(Map.class);
                }));
      }
      gate.countDown();
      List<Map<String, Object>> views = new ArrayList<>();
      for (Future<Map<String, Object>> future : futures) {
        views.add(future.get(60, TimeUnit.SECONDS));
      }
      assertThat(views).allSatisfy(v -> assertThat(v.get("status")).isEqualTo("REVOKED"));
      assertThat(views.stream().map(v -> v.get("version")).distinct().count()).isEqualTo(1);
    } finally {
      pool.shutdownNow();
    }
    Long version =
        owner.queryForObject(
            "SELECT status_version FROM credential_artifact WHERE id = ?",
            Long.class, UUID.fromString(stage.credentialId()));
    assertThat(version).isEqualTo(2);
  }
}
