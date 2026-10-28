package dev.sovra.verification;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.audit.AuditService;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.config.SovraMode;
import dev.sovra.consent.ConsentFixtures;
import dev.sovra.issuance.CredentialEncoder;
import dev.sovra.issuance.IssuanceEvidence;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.issuance.IssuerSigner;
import dev.sovra.issuance.KeyRef;
import dev.sovra.issuance.StatusEvidenceFetcher;
import dev.sovra.issuance.TrustSnapshotProvider;
import dev.sovra.issuance.WaltIdSdJwtVcEncoder;
import dev.sovra.ops.TelemetryService;
import dev.sovra.tenancy.TenantContext;
import dev.sovra.tenancy.TenantDataSource;
import dev.sovra.trust.TrustService;
import dev.sovra.verification.VerificationFixtures.Stage;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
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
 * SOV-036 verification parity: the walt-id SD-JWT VC path enforces
 * the same gates as the synthetic path — same consent approval,
 * expiry, revocation, trust, binding, and outage semantics —
 * while reading real SD-JWT VC artifacts. Runs in the synthetic
 * context and drives a {@code sdjwt-vc}-profiled service instance
 * directly, so both profiles are exercised against one database.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class WaltIdVerificationParityTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  @Autowired TrustService trust;

  @Autowired AuthorizationService authz;

  @Autowired AuditService audit;

  @Autowired TrustSnapshotProvider snapshots;

  @Autowired StatusEvidenceFetcher status;

  @Autowired IssuerSigner signer;

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

  /** Approved stage whose stored artifact is a real SD-JWT VC. */
  private Stage sdJwtStage(String tag) throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, tag);
    Map<String, Object> row = owner.queryForMap(
        "SELECT issuer_id, key_ref, expires_at, trust_snapshot_version"
            + " FROM credential_artifact WHERE id = ?",
        UUID.fromString(stage.credentialId()));
    KeyRef keyRef = KeyRef.decode(row.get("key_ref").toString());
    IssuanceEvidence evidence = new IssuanceEvidence(
        UUID.fromString(stage.credentialId()),
        row.get("issuer_id").toString(),
        keyRef,
        IssuanceFixtures.ADULT_VCT,
        Map.of("adultOver18", Boolean.TRUE),
        IssuanceFixtures.thumbprint(stage.holder()),
        clock.instant(),
        ((java.sql.Timestamp) row.get("expires_at")).toInstant(),
        ((Number) row.get("trust_snapshot_version")).longValue(),
        "/api/issuance/credentials/" + stage.credentialId() + "/status",
        stage.holder().jwk());
    CredentialEncoder.EncodedCredential encoded =
        new WaltIdSdJwtVcEncoder(signer).encode(evidence);
    assertThat(encoded.artifact()).contains("~");
    owner.update("UPDATE credential_artifact SET artifact = ? WHERE id = ?",
        encoded.artifact(), UUID.fromString(stage.credentialId()));
    return stage;
  }

  private String verifyWalt(Stage stage, String nonce) {
    return verifyWalt(stage, nonce, snapshots, status);
  }

  private String verifyWalt(
      Stage stage, String nonce, TrustSnapshotProvider provider, StatusEvidenceFetcher fetcher) {
    VerificationService instance = new VerificationService(authz, audit, provider, fetcher,
        new JdbcTemplate(new TenantDataSource(dataSource)), clock, mapper, telemetry,
        "sdjwt-vc", new SovraMode("demo"));
    ServiceAccountPrincipal principal = IssuanceFixtures.asPrincipal(stage.rp());
    VerificationService.VerifyRequest submission;
    try {
      submission = new VerificationService.VerifyRequest(
          UUID.fromString(stage.requestId()), nonce, ConsentFixtures.AUDIENCE,
          stage.holder().jwk(),
          VerificationFixtures.bindingProof(
              stage.holder(), stage.requestId(), nonce, ConsentFixtures.AUDIENCE, mapper));
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
    return new TransactionTemplate(transactions).execute(ignored -> {
      TenantContext.set(principal);
      try {
        return instance.verify(principal, submission);
      } finally {
        TenantContext.clear();
      }
    });
  }

  private String verifyWaltSubmission(Stage stage, VerificationService.VerifyRequest submission) {
    VerificationService instance = new VerificationService(authz, audit, snapshots, status,
        new JdbcTemplate(new TenantDataSource(dataSource)), clock, mapper, telemetry,
        "sdjwt-vc", new SovraMode("demo"));
    ServiceAccountPrincipal principal = IssuanceFixtures.asPrincipal(stage.rp());
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
  void waltProfileAcceptsSdJwtVc() throws Exception {
    Stage stage = sdJwtStage("walt-ok");
    JsonNode decided = mapper.readTree(verifyWalt(stage, VerificationFixtures.nonce()));
    assertThat(decided.get("outcome").asString()).isEqualTo("ACCEPTED");
    assertThat(decided.get("reasonCode").asString()).isEqualTo("OK");
    assertThat(decided.get("profile").asString())
        .isEqualTo(VerificationService.SDJWT_VC_PROFILE);
    assertThat(decided.get("trustSnapshot").asLong()).isPositive();

    // The receipt reads back with the same profile label.
    Map<String, Object> retrieved = VerificationFixtures.decision(
        client, stage.rp(), decided.get("decisionId").asString());
    assertThat(retrieved.get("outcome")).isEqualTo("ACCEPTED");
    assertThat(retrieved.get("profile")).isEqualTo(VerificationService.SDJWT_VC_PROFILE);
  }

  @Test
  void waltProfileRejectsSyntheticArtifact() throws Exception {
    // No artifact swap: the stored synthetic JWT must not verify as
    // SD-JWT VC.
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "walt-xsyn");
    JsonNode decided = mapper.readTree(verifyWalt(stage, VerificationFixtures.nonce()));
    assertThat(decided.get("outcome").asString()).isEqualTo("REJECTED");
    assertThat(decided.get("reasonCode").asString()).isEqualTo("ARTIFACT_INVALID");
  }

  @Test
  void syntheticProfileRejectsSdJwtArtifact() throws Exception {
    // The profiles are mutually exclusive: an SD-JWT VC must not
    // verify under the synthetic parser either.
    Stage stage = sdJwtStage("walt-xsd");
    Map<String, Object> decided = VerificationFixtures.verify(client, stage.rp(),
        VerificationFixtures.verifyBody(stage.holder(), stage.requestId(),
            VerificationFixtures.nonce(), ConsentFixtures.AUDIENCE, mapper));
    assertThat(decided.get("outcome")).isEqualTo("REJECTED");
  }

  @Test
  void waltProfilePreservesFreshnessGates() throws Exception {
    Stage stage = sdJwtStage("walt-fresh");
    // Revocation still rejects before any crypto runs.
    StatusEvidenceFetcher revoked = credentialId ->
        new StatusEvidenceFetcher.StatusEvidence(
            StatusEvidenceFetcher.Status.REVOKED, 2, clock.instant(),
            java.time.Duration.ofMinutes(15));
    JsonNode held = mapper.readTree(
        verifyWalt(stage, VerificationFixtures.nonce(), snapshots, revoked));
    assertThat(held.get("outcome").asString()).isEqualTo("REJECTED");
    assertThat(held.get("reasonCode").asString()).isEqualTo("CREDENTIAL_REVOKED");

    // Consent expiry still rejects with its own reason.
    owner.update("UPDATE proof_request SET expires_at = now() - INTERVAL '1 minute'"
        + " WHERE id = ?", UUID.fromString(stage.requestId()));
    JsonNode expired = mapper.readTree(verifyWalt(stage, VerificationFixtures.nonce()));
    assertThat(expired.get("outcome").asString()).isEqualTo("REJECTED");
    assertThat(expired.get("reasonCode").asString()).isEqualTo("CONSENT_EXPIRED");
  }

  @Test
  void waltProfileRejectsTamperedArtifact() throws Exception {
    Stage stage = sdJwtStage("walt-tamp");
    String stored = owner.queryForObject(
        "SELECT artifact FROM credential_artifact WHERE id = ?", String.class,
        UUID.fromString(stage.credentialId()));
    assertThat(stored).isNotNull();
    // Flip one character inside the issuer-signed JWT: the signature
    // must fail, not the parse.
    int dot = stored.indexOf('.');
    char replacement = stored.charAt(dot + 4) == 'A' ? 'B' : 'A';
    String tampered = stored.substring(0, dot + 4) + replacement + stored.substring(dot + 5);
    assertThat(tampered).isNotEqualTo(stored);
    owner.update("UPDATE credential_artifact SET artifact = ? WHERE id = ?",
        tampered, UUID.fromString(stage.credentialId()));
    JsonNode decided = mapper.readTree(verifyWalt(stage, VerificationFixtures.nonce()));
    assertThat(decided.get("outcome").asString()).isEqualTo("REJECTED");
    assertThat(decided.get("reasonCode").asString()).isEqualTo("ARTIFACT_SIGNATURE_INVALID");
  }

  @Test
  void waltProfileRejectsDisclosureTamper() throws Exception {
    Stage stage = sdJwtStage("walt-disc");
    String stored = owner.queryForObject(
        "SELECT artifact FROM credential_artifact WHERE id = ?", String.class,
        UUID.fromString(stage.credentialId()));
    assertThat(stored).isNotNull();
    // Flip one character inside the disclosure: its digest no longer
    // matches the signed payload, so the artifact must fail closed.
    int tilde = stored.indexOf('~');
    assertThat(tilde).isPositive();
    char replacement = stored.charAt(tilde + 4) == 'A' ? 'B' : 'A';
    owner.update("UPDATE credential_artifact SET artifact = ? WHERE id = ?",
        stored.substring(0, tilde + 4) + replacement + stored.substring(tilde + 5),
        UUID.fromString(stage.credentialId()));
    JsonNode decided = mapper.readTree(verifyWalt(stage, VerificationFixtures.nonce()));
    assertThat(decided.get("outcome").asString()).isEqualTo("REJECTED");
  }

  @Test
  void waltProfileRejectsStrippedDisclosures() throws Exception {
    Stage stage = sdJwtStage("walt-strip");
    String stored = owner.queryForObject(
        "SELECT artifact FROM credential_artifact WHERE id = ?", String.class,
        UUID.fromString(stage.credentialId()));
    assertThat(stored).isNotNull();
    // The issuer-signed JWT alone verifies cryptographically, but the
    // allowlisted claim is undisclosed: acceptance must still refuse.
    owner.update("UPDATE credential_artifact SET artifact = ? WHERE id = ?",
        stored.substring(0, stored.indexOf('~')), UUID.fromString(stage.credentialId()));
    JsonNode decided = mapper.readTree(verifyWalt(stage, VerificationFixtures.nonce()));
    assertThat(decided.get("outcome").asString()).isEqualTo("REJECTED");
    assertThat(decided.get("reasonCode").asString()).isEqualTo("CLAIMS_MISMATCH");
  }

  @Test
  void waltProfileReplaysByteIdentically() throws Exception {
    Stage stage = sdJwtStage("walt-replay");
    // One submission, sent twice: the binding proof is signed once, so
    // the retry is a true replay, not a conflicting second attempt.
    String nonce = VerificationFixtures.nonce();
    VerificationService.VerifyRequest submission = new VerificationService.VerifyRequest(
        UUID.fromString(stage.requestId()), nonce, ConsentFixtures.AUDIENCE,
        stage.holder().jwk(),
        VerificationFixtures.bindingProof(
            stage.holder(), stage.requestId(), nonce, ConsentFixtures.AUDIENCE, mapper));
    String first = verifyWaltSubmission(stage, submission);
    assertThat(mapper.readTree(first).get("outcome").asString()).isEqualTo("ACCEPTED");
    assertThat(verifyWaltSubmission(stage, submission)).isEqualTo(first);
    Integer count = owner.queryForObject(
        "SELECT COUNT(*) FROM verification_decision WHERE request_id = ?",
        Integer.class, UUID.fromString(stage.requestId()));
    assertThat(count).isEqualTo(1);
  }

  @Test
  void waltProfileFailsClosedOnTrustOutage() throws Exception {
    Stage stage = sdJwtStage("walt-out");
    TrustSnapshotProvider outage = Optional::empty;
    JsonNode decided = mapper.readTree(
        verifyWalt(stage, VerificationFixtures.nonce(), outage, status));
    assertThat(decided.get("outcome").asString()).isEqualTo("UNKNOWN");
    assertThat(decided.get("reasonCode").asString()).isEqualTo("TRUST_UNAVAILABLE");
  }

  @Test
  void waltProfileEnforcesHolderBinding() throws Exception {
    Stage stage = sdJwtStage("walt-bind");
    VerificationService instance = new VerificationService(authz, audit, snapshots, status,
        new JdbcTemplate(new TenantDataSource(dataSource)), clock, mapper, telemetry,
        "sdjwt-vc", new SovraMode("demo"));
    ServiceAccountPrincipal principal = IssuanceFixtures.asPrincipal(stage.rp());
    // Binding proof signed over a different nonce: consent and
    // verification must disagree loudly.
    String nonce = VerificationFixtures.nonce();
    JsonNode holderJwk = stage.holder().jwk();
    String wrongBinding;
    try {
      wrongBinding = VerificationFixtures.bindingProof(stage.holder(), stage.requestId(),
          VerificationFixtures.nonce(), ConsentFixtures.AUDIENCE, mapper);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
    VerificationService.VerifyRequest submission = new VerificationService.VerifyRequest(
        UUID.fromString(stage.requestId()), nonce, ConsentFixtures.AUDIENCE, holderJwk,
        wrongBinding);
    String response = new TransactionTemplate(transactions).execute(ignored -> {
      TenantContext.set(principal);
      try {
        return instance.verify(principal, submission);
      } finally {
        TenantContext.clear();
      }
    });
    JsonNode decided = mapper.readTree(response);
    assertThat(decided.get("outcome").asString()).isEqualTo("REJECTED");
    assertThat(decided.get("reasonCode").asString()).isEqualTo("BINDING_INVALID");
  }
}
