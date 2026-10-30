package dev.sovra.verification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.consent.ConsentFixtures;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.tenancy.TenantContext;
import dev.sovra.trust.TrustService;
import dev.sovra.verification.VerificationFixtures.Stage;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
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
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Verification failure proofs (FR-08, FR-19, FR-24, FR-31): every
 * independently invalid condition prevents acceptance with a safe
 * reason, conflicting follow-ups cannot rewrite stored decisions, and
 * strangers learn nothing.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class VerificationNegativeTests extends SovraAppRoleBase {

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

  private String submitForReason(Stage stage, Map<String, Object> body) {
    Map<String, Object> decided = VerificationFixtures.verify(client, stage.rp(), body);
    assertThat(decided.get("outcome")).isEqualTo("REJECTED");
    return decided.get("reasonCode").toString();
  }

  private Map<String, Object> freshBody(Stage stage) throws Exception {
    return VerificationFixtures.verifyBody(stage.holder(), stage.requestId(),
        VerificationFixtures.nonce(), ConsentFixtures.AUDIENCE, mapper);
  }

  @Test
  void tamperedArtifactSignatureRejects() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "sig");
    String artifact = owner.queryForObject(
        "SELECT artifact FROM credential_artifact WHERE id = ?", String.class,
        UUID.fromString(stage.credentialId()));
    assertThat(artifact).isNotNull();
    // Flip the first signature character inside the base64url
    // alphabet: the container still parses, but the decoded signature
    // bytes always change, so verification must fail. (The final
    // character is unusable for this: a 64-byte ECDSA signature ends
    // in pad-constrained bits, and flipping only those decodes to
    // identical bytes that still verify.)
    String[] parts = artifact.split("\\.", -1);
    assertThat(parts.length).isEqualTo(3);
    char first = parts[2].charAt(0);
    char flipped = first == 'A' ? 'B' : 'A';
    owner.update("UPDATE credential_artifact SET artifact = ? WHERE id = ?",
        parts[0] + "." + parts[1] + "." + flipped + parts[2].substring(1),
        UUID.fromString(stage.credentialId()));

    assertThat(submitForReason(stage, freshBody(stage)))
        .isEqualTo("ARTIFACT_SIGNATURE_INVALID");
  }

  @Test
  void nonSyntheticArtifactRejects() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "typ");
    String artifact = owner.queryForObject(
        "SELECT artifact FROM credential_artifact WHERE id = ?", String.class,
        UUID.fromString(stage.credentialId()));
    assertThat(artifact).isNotNull();
    String[] parts = artifact.split("\\.", -1);
    // Same payload and signature, but the content type no longer names
    // the synthetic profile: not verifiable on the synthetic path.
    String header = Base64.getUrlEncoder().withoutPadding().encodeToString(
        "{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":\"synth-1\"}"
            .getBytes(StandardCharsets.UTF_8));
    owner.update("UPDATE credential_artifact SET artifact = ? WHERE id = ?",
        header + "." + parts[1] + "." + parts[2], UUID.fromString(stage.credentialId()));

    assertThat(submitForReason(stage, freshBody(stage))).isEqualTo("ARTIFACT_INVALID");
  }

  @Test
  void revokedIssuerKeyRejects() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "key");
    owner.update(
        "UPDATE issuer_signing_key SET status = 'REVOKED'"
            + " WHERE issuer_id = ? AND key_id = 'synth-1' AND key_version = 1",
        IssuanceFixtures.ISSUER_ID);
    try {
      assertThat(submitForReason(stage, freshBody(stage))).isEqualTo("ISSUER_KEY_INACTIVE");
    } finally {
      owner.update(
          "UPDATE issuer_signing_key SET status = 'ACTIVE'"
              + " WHERE issuer_id = ? AND key_id = 'synth-1' AND key_version = 1",
          IssuanceFixtures.ISSUER_ID);
    }
  }

  @Test
  void restrictivePolicyDeniesAndCleanSnapshotRestores() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "policy");
    TrustService.SnapshotView current = trust.currentSnapshot().orElseThrow();
    List<TrustService.IssuerInput> issuers = current.issuers().stream()
        .map(i -> new TrustService.IssuerInput(i.issuerId(), i.displayName(), i.scope(),
            i.credentialTypes(), i.keyId(), i.keyVersion(), i.publicKeyJwk(), i.validFrom(),
            i.validThrough(), i.status().name()))
        .toList();
    // A policy naming a different RP: this request's RP is not covered.
    TrustService.PolicyInput restrictive = new TrustService.PolicyInput(
        "https://other.example/rp", "other purpose",
        List.of(IssuanceFixtures.ADULT_VCT), "MEDIUM");
    activateSnapshot(issuers, List.of(restrictive));
    try {
      assertThat(submitForReason(stage, freshBody(stage))).isEqualTo("POLICY_DENIED");
    } finally {
      // Restore a policy-free snapshot: later tests share this container.
      activateSnapshot(issuers, List.of());
    }
    Map<String, Object> retry =
        VerificationFixtures.verify(client, stage.rp(), freshBody(stage));
    assertThat(retry.get("outcome")).isEqualTo("ACCEPTED");
  }

  private void activateSnapshot(
      List<TrustService.IssuerInput> issuers, List<TrustService.PolicyInput> policies) {
    TestAccount maker = TestAccounts.create(owner, "policy-maker", Set.of("TRUST_ADMIN"));
    TestAccount checker = TestAccounts.create(owner, "policy-checker", Set.of("TRUST_ADMIN"));
    TenantContext.set(IssuanceFixtures.asPrincipal(maker));
    TrustService.ProposalResult result;
    try {
      result = trust.propose(IssuanceFixtures.asPrincipal(maker),
          new TrustService.ProposalInput(issuers, policies), "test: verification policy gate");
    } finally {
      TenantContext.clear();
    }
    TenantContext.set(IssuanceFixtures.asPrincipal(checker));
    try {
      trust.approve(IssuanceFixtures.asPrincipal(checker), result.proposalId());
      trust.activate(IssuanceFixtures.asPrincipal(checker), result.version());
    } finally {
      TenantContext.clear();
    }
  }

  @Test
  void pendingConsentRejects() throws Exception {
    Stage approved = VerificationFixtures.approvedStage(client, owner, mapper, "pending-base");
    // Same tenant, but a request the holder never approved.
    Map<String, Object> created = ConsentFixtures.create(client, approved.rp(),
        ConsentFixtures.createBody(UUID.fromString(approved.credentialId())));
    assertThat(created).isNotNull();
    String requestId = created.get("requestId").toString();
    Map<String, Object> body = VerificationFixtures.verifyBody(approved.holder(), requestId,
        VerificationFixtures.nonce(), ConsentFixtures.AUDIENCE, mapper);
    Map<String, Object> decided = VerificationFixtures.verify(client, approved.rp(), body);
    assertThat(decided.get("outcome")).isEqualTo("REJECTED");
    assertThat(decided.get("reasonCode")).isEqualTo("CONSENT_NOT_APPROVED");
  }

  @Test
  void deniedConsentRejects() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "deny-issuer", Set.of("ISSUER_OPS"));
    TestAccount rp = TestAccounts.createInTenant(
        owner, issuer.tenantId(), "deny-rp", Set.of("RP_CLIENT"));
    TestAccount agent = TestAccounts.createInTenant(
        owner, issuer.tenantId(), "deny-agent", Set.of("TENANT_MEMBER"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String credentialId = ConsentFixtures.issueCredential(client, issuer, holder, mapper);
    Map<String, Object> created = ConsentFixtures.create(
        client, rp, ConsentFixtures.createBody(UUID.fromString(credentialId)));
    assertThat(created).isNotNull();
    String requestId = created.get("requestId").toString();
    Map<String, Object> review = ConsentFixtures.review(client, rp, requestId);
    ConsentFixtures.decide(client, agent, requestId,
        ConsentFixtures.decideBody(holder, review, "deny", mapper));

    Map<String, Object> body = VerificationFixtures.verifyBody(holder, requestId,
        VerificationFixtures.nonce(), ConsentFixtures.AUDIENCE, mapper);
    Map<String, Object> decided = VerificationFixtures.verify(client, rp, body);
    assertThat(decided.get("outcome")).isEqualTo("REJECTED");
    assertThat(decided.get("reasonCode")).isEqualTo("CONSENT_NOT_APPROVED");
  }

  @Test
  void expiredRequestRejects() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "exp-req");
    owner.update("UPDATE proof_request SET expires_at = now() - INTERVAL '1 minute'"
        + " WHERE id = ?", UUID.fromString(stage.requestId()));
    assertThat(submitForReason(stage, freshBody(stage))).isEqualTo("CONSENT_EXPIRED");
  }

  @Test
  void revokedCredentialRejects() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "revoked");
    client.post().uri("/api/issuance/credentials/" + stage.credentialId() + "/revoke")
        .headers(stage.issuer().headers()).retrieve().toBodilessEntity();
    assertThat(submitForReason(stage, freshBody(stage))).isEqualTo("CREDENTIAL_REVOKED");
  }

  @Test
  void expiredCredentialRejects() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "exp-cred");
    owner.update("UPDATE credential_artifact SET expires_at = now() - INTERVAL '1 minute'"
        + " WHERE id = ?", UUID.fromString(stage.credentialId()));
    assertThat(submitForReason(stage, freshBody(stage))).isEqualTo("CREDENTIAL_EXPIRED");
  }

  @Test
  void wrongHolderRejects() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "wrong-holder");
    IssuanceFixtures.HolderKeys stranger = IssuanceFixtures.generateHolder(mapper);
    Map<String, Object> body = VerificationFixtures.verifyBody(stranger, stage.requestId(),
        VerificationFixtures.nonce(), ConsentFixtures.AUDIENCE, mapper);
    assertThat(submitForReason(stage, body)).isEqualTo("HOLDER_MISMATCH");
  }

  @Test
  void mismatchedBindingRejects() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "mismatch");
    IssuanceFixtures.HolderKeys stranger = IssuanceFixtures.generateHolder(mapper);
    String nonce = VerificationFixtures.nonce();
    // Right key, wrong signature: someone else signed this attempt.
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("requestId", stage.requestId());
    body.put("nonce", nonce);
    body.put("audience", ConsentFixtures.AUDIENCE);
    body.put("holderJwk", mapper.convertValue(stage.holder().jwk(), Map.class));
    body.put("bindingProof", VerificationFixtures.bindingProof(
        stranger, stage.requestId(), nonce, ConsentFixtures.AUDIENCE, mapper));
    assertThat(submitForReason(stage, body)).isEqualTo("BINDING_INVALID");

    // Right key, signature over a different audience: rebinding fails.
    String nonce2 = VerificationFixtures.nonce();
    Map<String, Object> rebound = new LinkedHashMap<>();
    rebound.put("requestId", stage.requestId());
    rebound.put("nonce", nonce2);
    rebound.put("audience", ConsentFixtures.AUDIENCE);
    rebound.put("holderJwk", mapper.convertValue(stage.holder().jwk(), Map.class));
    rebound.put("bindingProof", VerificationFixtures.bindingProof(
        stage.holder(), stage.requestId(), nonce2, "https://evil.example/cb", mapper));
    assertThat(submitForReason(stage, rebound)).isEqualTo("BINDING_INVALID");
  }

  @Test
  void audienceMismatchRejects() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "audience");
    // A well-formed binding for another session: the attempt is fresh
    // and holder-signed, but it does not match the consented audience.
    String nonce = VerificationFixtures.nonce();
    String foreign = "https://other.example/callback";
    Map<String, Object> body = VerificationFixtures.verifyBody(
        stage.holder(), stage.requestId(), nonce, foreign, mapper);
    assertThat(submitForReason(stage, body)).isEqualTo("AUDIENCE_MISMATCH");
  }

  @Test
  void conflictingNonceContentPreservesOriginal() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "conflict");
    String nonce = VerificationFixtures.nonce();
    Map<String, Object> original = VerificationFixtures.verifyBody(
        stage.holder(), stage.requestId(), nonce, ConsentFixtures.AUDIENCE, mapper);
    Map<String, Object> decided = VerificationFixtures.verify(client, stage.rp(), original);
    assertThat(decided.get("outcome")).isEqualTo("ACCEPTED");
    String decisionId = decided.get("decisionId").toString();

    // Same nonce, different session content: a follow-up that must not
    // rewrite the stored decision — accepted or otherwise.
    String foreign = "https://other.example/callback";
    Map<String, Object> followup = VerificationFixtures.verifyBody(
        stage.holder(), stage.requestId(), nonce, foreign, mapper);
    assertThatThrownBy(() -> VerificationFixtures.verify(client, stage.rp(), followup))
        .isInstanceOf(HttpClientErrorException.Conflict.class);

    Integer count = owner.queryForObject(
        "SELECT COUNT(*) FROM verification_decision WHERE request_id = ?",
        Integer.class, UUID.fromString(stage.requestId()));
    assertThat(count).isEqualTo(1);
    Map<String, Object> stored =
        VerificationFixtures.decision(client, stage.rp(), decisionId);
    assertThat(stored.get("outcome")).isEqualTo("ACCEPTED");
    assertThat(stored.get("decisionId")).isEqualTo(decisionId);
  }

  @Test
  void unknownRequestIsEmpty404() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "unknown");
    String missing = "00000000-0000-0000-0000-000000000000";
    Map<String, Object> body = VerificationFixtures.verifyBody(stage.holder(), missing,
        VerificationFixtures.nonce(), ConsentFixtures.AUDIENCE, mapper);
    assertEmpty404(() -> VerificationFixtures.verify(client, stage.rp(), body));
    assertEmpty404(() -> VerificationFixtures.decision(client, stage.rp(), missing));
    Integer count = owner.queryForObject(
        "SELECT COUNT(*) FROM verification_decision WHERE request_id = ?",
        Integer.class, UUID.fromString(missing));
    assertThat(count).isZero();
  }

  @Test
  void malformedSubmissionsAreRejectedWithoutDecisions() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "malformed");
    Map<String, Object> badNonce = freshBody(stage);
    badNonce.put("nonce", "short");
    assertThatThrownBy(() -> VerificationFixtures.verify(client, stage.rp(), badNonce))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);

    Map<String, Object> missingProof = freshBody(stage);
    missingProof.remove("bindingProof");
    assertThatThrownBy(() -> VerificationFixtures.verify(client, stage.rp(), missingProof))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);

    Map<String, Object> blankAudience = freshBody(stage);
    blankAudience.put("audience", "  ");
    assertThatThrownBy(() -> VerificationFixtures.verify(client, stage.rp(), blankAudience))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);

    Integer count = owner.queryForObject(
        "SELECT COUNT(*) FROM verification_decision WHERE request_id = ?",
        Integer.class, UUID.fromString(stage.requestId()));
    assertThat(count).isZero();
  }

  @Test
  void strangersLearnNothing() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "stranger");
    String nonce = VerificationFixtures.nonce();
    Map<String, Object> decided = VerificationFixtures.verify(client, stage.rp(),
        VerificationFixtures.verifyBody(stage.holder(), stage.requestId(), nonce,
            ConsentFixtures.AUDIENCE, mapper));
    assertThat(decided.get("outcome")).isEqualTo("ACCEPTED");
    String decisionId = decided.get("decisionId").toString();

    TestAccount stranger = TestAccounts.create(owner, "v-stranger", Set.of("RP_CLIENT"));
    String missing = "00000000-0000-0000-0000-000000000000";
    for (String requestId : new String[] {stage.requestId(), missing}) {
      Map<String, Object> probe = VerificationFixtures.verifyBody(stage.holder(), requestId,
          VerificationFixtures.nonce(), ConsentFixtures.AUDIENCE, mapper);
      assertEmpty404(() -> VerificationFixtures.verify(client, stranger, probe));
    }
    for (String id : new String[] {decisionId, missing}) {
      assertEmpty404(() -> VerificationFixtures.decision(client, stranger, id));
    }
  }

  private static void assertEmpty404(org.assertj.core.api.ThrowableAssert.ThrowingCallable call) {
    assertThatThrownBy(call)
        .isInstanceOf(HttpClientErrorException.NotFound.class)
        .satisfies(e -> {
          String payload =
              ((HttpClientErrorException.NotFound) e).getResponseBodyAsString();
          assertThat(payload == null || payload.isEmpty()).isTrue();
        });
  }

  @Test
  void wrongRolesAreDeniedAndAudited() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "roles");
    String nonce = VerificationFixtures.nonce();
    Map<String, Object> decided = VerificationFixtures.verify(client, stage.rp(),
        VerificationFixtures.verifyBody(stage.holder(), stage.requestId(), nonce,
            ConsentFixtures.AUDIENCE, mapper));
    String decisionId = decided.get("decisionId").toString();

    TestAccount admin = TestAccounts.createInTenant(
        owner, stage.rp().tenantId(), "v-admin", Set.of("TRUST_ADMIN"));
    TestAccount ops = TestAccounts.createInTenant(
        owner, stage.rp().tenantId(), "v-ops", Set.of("ISSUER_OPS"));

    // Only RP_CLIENT submits verifications.
    assertThatThrownBy(() -> VerificationFixtures.verify(client, admin, freshBody(stage)))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(() -> VerificationFixtures.verify(client, ops, freshBody(stage)))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(
            () -> VerificationFixtures.verify(client, stage.holderAgent(), freshBody(stage)))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);

    // Retrieval needs TENANT_MEMBER or RP_CLIENT.
    assertThatThrownBy(() -> VerificationFixtures.decision(client, admin, decisionId))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(() -> VerificationFixtures.decision(client, ops, decisionId))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    Map<String, Object> agentRead =
        VerificationFixtures.decision(client, stage.holderAgent(), decisionId);
    assertThat(agentRead.get("outcome")).isEqualTo("ACCEPTED");

    // Denial evidence persists on the read path: reads are not wrapped in
    // a business transaction, so the audit commit survives the 403.
    Map<String, Object> audit =
        owner.queryForMap(
            "SELECT * FROM audit_event WHERE tenant_id = ? AND action = 'READ_VERIFICATION'"
                + " AND decision = 'DENY' ORDER BY occurred_at DESC LIMIT 1",
            stage.rp().tenantId());
    assertThat(audit.get("reason_code")).isEqualTo("MISSING_ROLE");
  }

  @Test
  void anonymousCallsAreRejected() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "anon");
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/verification/presentations")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(freshBody(stage))
                    .retrieve()
                    .body(String.class))
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
    assertThatThrownBy(
            () ->
                client
                    .get()
                    .uri("/api/verification/decisions/00000000-0000-0000-0000-000000000000")
                    .retrieve()
                    .body(String.class))
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
  }
}
