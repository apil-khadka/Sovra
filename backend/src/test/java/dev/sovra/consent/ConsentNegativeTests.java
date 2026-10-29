package dev.sovra.consent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import java.time.Instant;
import java.util.LinkedHashMap;
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
 * Consent failure proofs (FR-07, FR-20, INV-05): refusal, inactivity,
 * scope edits, wrong holder, and expired consent or credentials never
 * produce an authorized presentation, and strangers learn nothing.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ConsentNegativeTests extends SovraAppRoleBase {

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

  private record Stage(
      TestAccount issuer, TestAccount rp, TestAccount holderAgent,
      IssuanceFixtures.HolderKeys holder, String credentialId, String requestId,
      Map<String, Object> review) {}

  private Stage stage(String tag) throws Exception {
    TestAccount issuer = TestAccounts.create(owner, tag + "-issuer", Set.of("ISSUER_OPS"));
    TestAccount rp = TestAccounts.createInTenant(
        owner, issuer.tenantId(), tag + "-rp", Set.of("RP_CLIENT"));
    TestAccount holderAgent = TestAccounts.createInTenant(
        owner, issuer.tenantId(), tag + "-agent", Set.of("TENANT_MEMBER"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String credentialId = ConsentFixtures.issueCredential(client, issuer, holder, mapper);
    Map<String, Object> created = ConsentFixtures.create(
        client, rp, ConsentFixtures.createBody(UUID.fromString(credentialId)));
    assertThat(created).isNotNull();
    String requestId = created.get("requestId").toString();
    Map<String, Object> review = ConsentFixtures.review(client, rp, requestId);
    return new Stage(issuer, rp, holderAgent, holder, credentialId, requestId, review);
  }

  private void assertBadRequest(Stage stage, Map<String, Object> review, String decision)
      throws Exception {
    Map<String, Object> body =
        ConsentFixtures.decideBody(stage.holder(), review, decision, mapper);
    assertThatThrownBy(() -> ConsentFixtures.decide(client, stage.holderAgent(),
            stage.requestId(), body))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  private void assertNoPresentation(Stage stage) {
    assertThatThrownBy(
            () ->
                client
                    .get()
                    .uri("/api/consent/requests/" + stage.requestId() + "/presentation")
                    .headers(stage.rp().headers())
                    .retrieve()
                    .body(String.class))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
  }

  private static Map<String, Object> tampered(Map<String, Object> review, String field,
      Object value) {
    Map<String, Object> copy = new LinkedHashMap<>(review);
    copy.put(field, value);
    return copy;
  }

  @Test
  void inactivityExpiresRequestWithoutPresentation() throws Exception {
    Stage stage = stage("inactive");
    owner.update("UPDATE proof_request SET expires_at = now() - INTERVAL '1 minute'"
        + " WHERE id = ?", UUID.fromString(stage.requestId()));

    Map<String, Object> review =
        ConsentFixtures.review(client, stage.rp(), stage.requestId());
    assertThat(review.get("state")).isEqualTo("UNAVAILABLE");

    assertBadRequest(stage, stage.review(), "approve");
    assertNoPresentation(stage);
  }

  @Test
  void scopeEditsInvalidateConsent() throws Exception {
    Stage stage = stage("scope");
    Map<String, Object> review = stage.review();
    assertBadRequest(stage, tampered(review, "rpId", "https://evil.example/rp"), "approve");
    assertBadRequest(stage, tampered(review, "audience", "https://evil.example/cb"), "approve");
    assertBadRequest(stage, tampered(review, "purpose", "edited purpose"), "approve");
    assertBadRequest(stage, tampered(review, "planHash", ConsentFixtures.planHash()), "approve");
    assertBadRequest(stage, tampered(review, "challenge", ConsentFixtures.challenge()), "approve");
    assertBadRequest(stage, tampered(review, "expiresAt",
        Instant.now().plusSeconds(7200).toString()), "approve");
    assertBadRequest(stage, tampered(review, "requestId", UUID.randomUUID().toString()),
        "approve");
    // The decision word itself is bound: a denial signature cannot approve.
    Map<String, Object> body =
        ConsentFixtures.decideBody(stage.holder(), review, "deny", mapper);
    body.put("decision", "approve");
    assertThatThrownBy(() -> ConsentFixtures.decide(client, stage.holderAgent(),
            stage.requestId(), body))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    // None of the failed attempts decided or delivered anything.
    Map<String, Object> reread =
        ConsentFixtures.review(client, stage.rp(), stage.requestId());
    assertThat(reread.get("state")).isEqualTo("PENDING");
    assertNoPresentation(stage);
  }

  @Test
  void unlistedClaimsAreRejectedAtCreation() throws Exception {
    Stage stage = stage("claims");
    Map<String, Object> widened =
        ConsentFixtures.createBody(UUID.fromString(stage.credentialId()));
    widened.put("claims", Map.of("adultOver18", Boolean.TRUE, "dob", "1990-01-01"));
    assertThatThrownBy(() -> ConsentFixtures.create(client, stage.rp(), widened))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    Map<String, Object> flipped =
        ConsentFixtures.createBody(UUID.fromString(stage.credentialId()));
    flipped.put("claims", Map.of("adultOver18", Boolean.FALSE));
    assertThatThrownBy(() -> ConsentFixtures.create(client, stage.rp(), flipped))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void wrongHolderCannotDecide() throws Exception {
    Stage stage = stage("wrong-holder");
    IssuanceFixtures.HolderKeys stranger = IssuanceFixtures.generateHolder(mapper);
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("decision", "approve");
    body.put("holderJwk", mapper.convertValue(stranger.jwk(), Map.class));
    body.put("consentProof",
        ConsentFixtures.consentProof(stranger, stage.review(), "approve", mapper));
    assertThatThrownBy(() -> ConsentFixtures.decide(client, stage.holderAgent(),
            stage.requestId(), body))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    assertNoPresentation(stage);
  }

  @Test
  void mismatchedKeyAndSignatureCannotDecide() throws Exception {
    Stage stage = stage("mismatch");
    IssuanceFixtures.HolderKeys stranger = IssuanceFixtures.generateHolder(mapper);
    // Right key, wrong signature: the proof was signed by someone else.
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("decision", "approve");
    body.put("holderJwk", mapper.convertValue(stage.holder().jwk(), Map.class));
    body.put("consentProof",
        ConsentFixtures.consentProof(stranger, stage.review(), "approve", mapper));
    assertThatThrownBy(() -> ConsentFixtures.decide(client, stage.holderAgent(),
            stage.requestId(), body))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    assertNoPresentation(stage);
  }

  @Test
  void secondDecisionConflicts() throws Exception {
    Stage stage = stage("twice");
    ConsentFixtures.decide(client, stage.holderAgent(), stage.requestId(),
        ConsentFixtures.decideBody(stage.holder(), stage.review(), "approve", mapper));
    assertThatThrownBy(
            () ->
                ConsentFixtures.decide(client, stage.holderAgent(), stage.requestId(),
                    ConsentFixtures.decideBody(stage.holder(),
                        ConsentFixtures.review(client, stage.rp(), stage.requestId()),
                        "deny", mapper)))
        .isInstanceOf(HttpClientErrorException.Conflict.class);

    Stage denied = stage("twice-denied");
    ConsentFixtures.decide(client, denied.holderAgent(), denied.requestId(),
        ConsentFixtures.decideBody(denied.holder(), denied.review(), "deny", mapper));
    assertThatThrownBy(
            () ->
                ConsentFixtures.decide(client, denied.holderAgent(), denied.requestId(),
                    ConsentFixtures.decideBody(denied.holder(),
                        ConsentFixtures.review(client, denied.rp(), denied.requestId()),
                        "approve", mapper)))
        .isInstanceOf(HttpClientErrorException.Conflict.class);
    assertNoPresentation(denied);
  }

  @Test
  void revokedCredentialBlocksDecision() throws Exception {
    Stage stage = stage("revoked-pending");
    client
        .post()
        .uri("/api/issuance/credentials/" + stage.credentialId() + "/revoke")
        .headers(stage.issuer().headers())
        .retrieve()
        .toBodilessEntity();

    Map<String, Object> review =
        ConsentFixtures.review(client, stage.rp(), stage.requestId());
    assertThat(review.get("state")).isEqualTo("UNAVAILABLE");

    assertBadRequest(stage, stage.review(), "approve");
    assertNoPresentation(stage);
  }

  @Test
  void revokedCredentialWithdrawsPresentation() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "rvk-issuer",
        Set.of("ISSUER_OPS", "RP_CLIENT", "TENANT_MEMBER"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String credentialId = ConsentFixtures.issueCredential(client, issuer, holder, mapper);
    Map<String, Object> created = ConsentFixtures.create(
        client, issuer, ConsentFixtures.createBody(UUID.fromString(credentialId)));
    assertThat(created).isNotNull();
    String requestId = created.get("requestId").toString();
    Map<String, Object> review = ConsentFixtures.review(client, issuer, requestId);
    ConsentFixtures.decide(client, issuer, requestId,
        ConsentFixtures.decideBody(holder, review, "approve", mapper));
    assertThat(ConsentFixtures.review(client, issuer, requestId).get("state"))
        .isEqualTo("VERIFIED");

    client
        .post()
        .uri("/api/issuance/credentials/" + credentialId + "/revoke")
        .headers(issuer.headers())
        .retrieve()
        .toBodilessEntity();

    Map<String, Object> reread = ConsentFixtures.review(client, issuer, requestId);
    assertThat(reread.get("state")).isEqualTo("UNAVAILABLE");
    assertThatThrownBy(
            () ->
                client
                    .get()
                    .uri("/api/consent/requests/" + requestId + "/presentation")
                    .headers(issuer.headers())
                    .retrieve()
                    .body(String.class))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
  }

  @Test
  void strangersLearnNothing() throws Exception {
    Stage stage = stage("stranger");
    TestAccount stranger = TestAccounts.create(owner, "stranger", Set.of("RP_CLIENT"));
    String missing = "00000000-0000-0000-0000-000000000000";
    for (String id : new String[] {stage.requestId(), missing}) {
      assertEmpty404(() -> client.get().uri("/api/consent/requests/" + id)
          .headers(stranger.headers()).retrieve().body(String.class));
      assertEmpty404(() -> client.get().uri("/api/consent/requests/" + id + "/presentation")
          .headers(stranger.headers()).retrieve().body(String.class));
      Map<String, Object> body = new LinkedHashMap<>();
      body.put("decision", "approve");
      body.put("holderJwk", mapper.convertValue(stage.holder().jwk(), Map.class));
      body.put("consentProof", "x.y.z");
      assertEmpty404(() -> client.post().uri("/api/consent/requests/" + id + "/decision")
          .headers(stranger.headers()).contentType(MediaType.APPLICATION_JSON).body(body)
          .retrieve().body(String.class));
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
    Stage stage = stage("roles");
    TestAccount admin = TestAccounts.createInTenant(
        owner, stage.rp().tenantId(), "roles-admin", Set.of("TRUST_ADMIN"));
    TestAccount ops = TestAccounts.createInTenant(
        owner, stage.rp().tenantId(), "roles-ops", Set.of("ISSUER_OPS"));

    // Only RP_CLIENT opens requests.
    assertThatThrownBy(() -> ConsentFixtures.create(client, admin,
            ConsentFixtures.createBody(UUID.fromString(stage.credentialId()))))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(() -> ConsentFixtures.create(client, ops,
            ConsentFixtures.createBody(UUID.fromString(stage.credentialId()))))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(() -> ConsentFixtures.create(client, stage.holderAgent(),
            ConsentFixtures.createBody(UUID.fromString(stage.credentialId()))))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);

    // Only TENANT_MEMBER/RP_CLIENT read or deliver decisions.
    assertThatThrownBy(() -> ConsentFixtures.review(client, admin, stage.requestId()))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(() -> ConsentFixtures.review(client, ops, stage.requestId()))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(
            () ->
                ConsentFixtures.decide(client, admin, stage.requestId(),
                    ConsentFixtures.decideBody(stage.holder(), stage.review(), "deny", mapper)))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);

    // Denial evidence persists on the read path: reads are not wrapped in
    // a business transaction, so the audit commit survives the 403.
    Map<String, Object> audit =
        owner.queryForMap(
            "SELECT * FROM audit_event WHERE tenant_id = ? AND action = 'READ_CONSENT'"
                + " AND decision = 'DENY' ORDER BY occurred_at DESC LIMIT 1",
            stage.rp().tenantId());
    assertThat(audit.get("reason_code")).isEqualTo("MISSING_ROLE");
  }

  @Test
  void anonymousCallsAreRejected() throws Exception {
    Stage stage = stage("anon");
    assertThatThrownBy(() -> client.get().uri("/api/consent/requests/" + stage.requestId())
            .retrieve().body(String.class))
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
    assertThatThrownBy(() -> client.get()
            .uri("/api/consent/requests/" + stage.requestId() + "/presentation")
            .retrieve().body(String.class))
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/consent/requests")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(ConsentFixtures.createBody(UUID.fromString(stage.credentialId())))
                    .retrieve()
                    .body(String.class))
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
  }

  @Test
  void malformedRequestsAreRejected() throws Exception {
    Stage stage = stage("malformed");
    Map<String, Object> badHash =
        ConsentFixtures.createBody(UUID.fromString(stage.credentialId()));
    badHash.put("planHash", "not-hex");
    assertThatThrownBy(() -> ConsentFixtures.create(client, stage.rp(), badHash))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);

    Map<String, Object> badChallenge =
        ConsentFixtures.createBody(UUID.fromString(stage.credentialId()));
    badChallenge.put("challenge", "short");
    assertThatThrownBy(() -> ConsentFixtures.create(client, stage.rp(), badChallenge))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);

    Map<String, Object> past =
        ConsentFixtures.createBody(UUID.fromString(stage.credentialId()));
    past.put("expiresAt", Instant.now().minusSeconds(60).toString());
    assertThatThrownBy(() -> ConsentFixtures.create(client, stage.rp(), past))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);

    Map<String, Object> tooFar =
        ConsentFixtures.createBody(UUID.fromString(stage.credentialId()));
    tooFar.put("expiresAt", Instant.now().plusSeconds(25 * 3600).toString());
    assertThatThrownBy(() -> ConsentFixtures.create(client, stage.rp(), tooFar))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);

    Map<String, Object> unknownCredential = ConsentFixtures.createBody(UUID.randomUUID());
    assertThatThrownBy(() -> ConsentFixtures.create(client, stage.rp(), unknownCredential))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);

    Map<String, Object> missing = new LinkedHashMap<>();
    missing.put("rpId", ConsentFixtures.RP_ID);
    assertThatThrownBy(() -> ConsentFixtures.create(client, stage.rp(), missing))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }
}
