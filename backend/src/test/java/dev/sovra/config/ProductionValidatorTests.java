package dev.sovra.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraPostgresBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.audit.AuditService;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.consent.ConsentFixtures;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.issuance.KmsSigner;
import dev.sovra.issuance.StatusEvidenceFetcher;
import dev.sovra.trust.TrustSnapshotProvider;
import dev.sovra.ops.TelemetryService;
import dev.sovra.tenancy.TenantContext;
import dev.sovra.tenancy.TenantDataSource;
import dev.sovra.trust.InvalidProposalException;
import dev.sovra.trust.TrustService;
import dev.sovra.vault.KmsVaultKekProvider;
import dev.sovra.verification.VerificationFixtures;
import dev.sovra.verification.VerificationService;
import java.time.Clock;
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
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Production-entry enforcement against real PostgreSQL (SOV-040):
 * the startup scan refuses synthetic data, and the per-call gates
 * (activation, quorum, verification) refuse synthetic authority even
 * when reached directly.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ProductionValidatorTests extends SovraPostgresBase {

  @LocalServerPort int port;

  @Autowired DataSource dataSource;

  @Autowired AuthorizationService authz;

  @Autowired AuditService audit;

  @Autowired TrustSnapshotProvider snapshots;

  @Autowired StatusEvidenceFetcher status;

  @Autowired PlatformTransactionManager transactions;

  @Autowired Clock clock;

  @Autowired ObjectMapper mapper;

  @Autowired TelemetryService telemetry;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
  }

  @Test
  void entryScanRefusesTheSyntheticGenesis() {
    ProductionStartupValidator validator = new ProductionStartupValidator(
        new SovraMode("production"), new KmsSigner(), new KmsVaultKekProvider(),
        ownerDataSource(), "sdjwt-vc", "");
    assertThatThrownBy(() -> validator.run(null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("production entry refused");
  }

  @Test
  void entryScanPassesWithoutSyntheticMarkers() {
    // The sealed genesis cannot be scrubbed, so the pass path runs
    // against a minimal clean schema on a dedicated connection: the
    // scan must accept real rows and would still catch markers.
    com.zaxxer.hikari.HikariDataSource hikari =
        (com.zaxxer.hikari.HikariDataSource) ownerDataSource();
    org.springframework.jdbc.datasource.SingleConnectionDataSource clean =
        new org.springframework.jdbc.datasource.SingleConnectionDataSource(
            hikari.getJdbcUrl(), hikari.getUsername(), hikari.getPassword(), true);
    try {
      JdbcTemplate setup = new JdbcTemplate(clean);
      setup.execute("DROP SCHEMA IF EXISTS cleanprod CASCADE");
      setup.execute("CREATE SCHEMA cleanprod");
      setup.execute("SET search_path = cleanprod");
      setup.execute("CREATE TABLE issuer_record (scope TEXT, issuer_id TEXT)");
      setup.execute("CREATE TABLE issuer_signing_key (issuer_id TEXT)");
      setup.execute("CREATE TABLE tenant (slug TEXT)");
      setup.update(
          "INSERT INTO issuer_record (scope, issuer_id) VALUES ('adult-status',"
              + " 'https://issuer.example/np-1')");
      ProductionStartupValidator validator = new ProductionStartupValidator(
          new SovraMode("production"), new KmsSigner(), new KmsVaultKekProvider(),
          clean, "sdjwt-vc", "");
      validator.run(null);
      setup.update("INSERT INTO tenant (slug) VALUES ('sovra-demo')");
      assertThatThrownBy(() -> validator.run(null))
          .isInstanceOf(IllegalStateException.class)
          .hasMessageContaining("demo seed tenant");
    } finally {
      new JdbcTemplate(clean).execute("DROP SCHEMA IF EXISTS cleanprod CASCADE");
      clean.destroy();
    }
  }

  @Test
  void productionActivationRefusesSyntheticSnapshots() throws Exception {
    TrustService demo = new TrustService(
        authz, audit, dataSource, clock, mapper, new SovraMode("demo"));
    TrustService production = new TrustService(
        authz, audit, dataSource, clock, mapper, new SovraMode("production"));
    TestAccount maker = TestAccounts.create(owner, "prod-syn-maker", Set.of("TRUST_ADMIN"));
    TestAccount checker = TestAccounts.create(owner, "prod-syn-checker", Set.of("TRUST_ADMIN"));
    TenantContext.set(IssuanceFixtures.asPrincipal(maker));
    TrustService.ProposalResult proposal;
    try {
      proposal = demo.propose(
          IssuanceFixtures.asPrincipal(maker), syntheticProposalInput(), "synthetic v2");
      TenantContext.set(IssuanceFixtures.asPrincipal(checker));
      demo.approve(IssuanceFixtures.asPrincipal(checker), proposal.proposalId());
    } finally {
      TenantContext.clear();
    }
    TenantContext.set(IssuanceFixtures.asPrincipal(checker));
    try {
      assertThatThrownBy(() -> production.activate(
              IssuanceFixtures.asPrincipal(checker), proposal.version()))
          .isInstanceOf(InvalidProposalException.class)
          .hasMessageContaining("synthetic snapshot cannot activate");
    } finally {
      TenantContext.clear();
    }
  }

  @Test
  void productionApproveRefusesMachineQuorums() throws Exception {
    TrustService production = new TrustService(
        authz, audit, dataSource, clock, mapper, new SovraMode("production"));
    TestAccount maker = TestAccounts.create(owner, "prod-maker", Set.of("TRUST_ADMIN"));
    TestAccount checker = TestAccounts.create(owner, "prod-checker", Set.of("TRUST_ADMIN"));
    TenantContext.set(IssuanceFixtures.asPrincipal(maker));
    TrustService.ProposalResult proposal =
        production.propose(IssuanceFixtures.asPrincipal(maker), proposalInput(), "prod");
    TenantContext.set(IssuanceFixtures.asPrincipal(checker));
    try {
      assertThatThrownBy(() -> production.approve(IssuanceFixtures.asPrincipal(checker),
              proposal.proposalId()))
          .isInstanceOf(ForbiddenException.class)
          .hasMessageContaining("ASSURANCE_INSUFFICIENT");
    } finally {
      TenantContext.clear();
    }
    // The refusal is platform evidence (global resource), matched by
    // proposal; the decision row was never written.
    Map<String, Object> denial =
        owner.queryForMap(
            "SELECT decision, reason_code FROM audit_event"
                + " WHERE tenant_id IS NULL AND action = 'APPROVE_TRUST_CHANGE'"
                + " AND resource_id = ? ORDER BY occurred_at DESC LIMIT 1",
            proposal.proposalId().toString());
    assertThat(denial.get("decision")).isEqualTo("DENY");
    assertThat(denial.get("reason_code")).isEqualTo("ASSURANCE_INSUFFICIENT");
    assertThat(
            owner.queryForObject(
                "SELECT COUNT(*) FROM trust_proposal_decision WHERE proposal_id = ?",
                Integer.class,
                proposal.proposalId()))
        .isZero();
  }

  @Test
  void productionVerificationRejectsTheSyntheticProfile() throws Exception {
    IssuanceFixtures.ensureSyntheticIssuer(owner,
        new TrustService(authz, audit, dataSource, clock, mapper, new SovraMode("demo")), mapper);
    VerificationFixtures.Stage stage =
        VerificationFixtures.approvedStage(client, owner, mapper, "prodv");
    VerificationService production = new VerificationService(authz, audit, snapshots, status,
        new JdbcTemplate(new TenantDataSource(dataSource)), clock, mapper, telemetry,
        "synthetic", new SovraMode("production"));
    ServiceAccountPrincipal principal = IssuanceFixtures.asPrincipal(stage.rp());
    String nonce = VerificationFixtures.nonce();
    VerificationService.VerifyRequest submission = new VerificationService.VerifyRequest(
        UUID.fromString(stage.requestId()), nonce, ConsentFixtures.AUDIENCE,
        stage.holder().jwk(),
        VerificationFixtures.bindingProof(
            stage.holder(), stage.requestId(), nonce, ConsentFixtures.AUDIENCE, mapper));
    String response = new TransactionTemplate(transactions).execute(ignored -> {
      TenantContext.set(principal);
      try {
        return production.verify(principal, submission);
      } finally {
        TenantContext.clear();
      }
    });
    assertThat(response).isNotNull();
    JsonNode decided = mapper.readTree(response);
    assertThat(decided.get("outcome").asString()).isEqualTo("REJECTED");
    assertThat(decided.get("reasonCode").asString()).isEqualTo("SYNTHETIC_PROFILE_REJECTED");
  }

  private TrustService.ProposalInput syntheticProposalInput() throws Exception {
    JsonNode jwk = mapper.readTree(
        "{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"syn-k\","
            + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
            + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}");
    TrustService.IssuerInput issuer = new TrustService.IssuerInput(
        "https://sovra.example/issuers/test-syn", "Test synthetic", "synthetic-only",
        java.util.List.of("https://sovra.example/vct/adult-status/1"),
        "syn-k", 1, jwk, clock.instant().minusSeconds(60),
        clock.instant().plusSeconds(3600), "ACTIVE");
    TrustService.PolicyInput policy = new TrustService.PolicyInput(
        "demo-rp", "age-gate",
        java.util.List.of("https://sovra.example/vct/adult-status/1"), "MEDIUM");
    return new TrustService.ProposalInput(java.util.List.of(issuer), java.util.List.of(policy));
  }

  private TrustService.ProposalInput proposalInput() throws Exception {
    JsonNode jwk = mapper.readTree(
        "{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"prod-k\","
            + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
            + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}");
    TrustService.IssuerInput issuer = new TrustService.IssuerInput("np-prod-issuer",
        "Prod issuer", "adult-status", java.util.List.of("https://sovra.example/vct/x"),
        "prod-k", 1, jwk, clock.instant().minusSeconds(60),
        clock.instant().plusSeconds(3600), "ACTIVE");
    TrustService.PolicyInput policy = new TrustService.PolicyInput(
        "demo-rp", "age-gate", java.util.List.of("https://sovra.example/vct/x"), "MEDIUM");
    return new TrustService.ProposalInput(java.util.List.of(issuer), java.util.List.of(policy));
  }
}
