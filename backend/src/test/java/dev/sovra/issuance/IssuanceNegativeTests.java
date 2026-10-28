package dev.sovra.issuance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.trust.TrustService;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
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
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Adversarial issuance cases: authz, scope, proofs, keys, replays. Boots
 * as the least-privilege role, like production, so row-level security
 * applies to every read below.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class IssuanceNegativeTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  @Autowired TrustService trust;

  @Autowired IssuerSigner signer;

  @Autowired ObjectMapper mapper;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() throws Exception {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
    IssuanceFixtures.ensureSyntheticIssuer(owner, trust, mapper);
  }

  private Map<String, Object> issueBody(IssuanceFixtures.HolderKeys holder, String key)
      throws Exception {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("issuerId", IssuanceFixtures.ISSUER_ID);
    body.put("vct", IssuanceFixtures.ADULT_VCT);
    body.put("holderJwk", mapper.convertValue(holder.jwk(), Map.class));
    body.put("holderProof", IssuanceFixtures.proof(holder, key, IssuanceFixtures.ADULT_VCT, mapper));
    body.put("claims", Map.of("adultOver18", Boolean.TRUE));
    body.put("expiresAt", Instant.now().plusSeconds(3600).toString());
    return body;
  }

  private String issueRaw(TestAccount issuer, String key, Map<String, Object> body) {
    return client
        .post()
        .uri("/api/issuance/credentials")
        .headers(
            h -> {
              issuer.headers().accept(h);
              h.set("Idempotency-Key", key);
            })
        .contentType(MediaType.APPLICATION_JSON)
        .body(body)
        .retrieve()
        .body(String.class);
  }

  @Test
  void memberCannotIssueButReadsOwnTenant() throws Exception {
    TestAccount member = TestAccounts.create(owner, "no-issue", Set.of("TENANT_MEMBER"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String key = "neg-member-" + UUID.randomUUID();
    assertThatThrownBy(() -> issueRaw(member, key, issueBody(holder, key)))
        .isInstanceOf(HttpClientErrorException.Forbidden.class)
        .satisfies(
            e -> assertThat(((HttpClientErrorException) e).getResponseBodyAsString())
                .contains("MISSING_ROLE"));
    // The read action permits; RLS hides the unknown object as 404.
    assertThatThrownBy(
            () -> client.get().uri("/api/issuance/credentials/" + UUID.randomUUID())
                .headers(member.headers()).retrieve().toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.NotFound.class)
        .satisfies(
            e -> assertThat(((HttpClientErrorException) e).getResponseBodyAsString()).isEmpty());
  }

  @Test
  void unknownIssuerIsRejected() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "neg-issuer", Set.of("ISSUER_OPS"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String key = "neg-unknown-" + UUID.randomUUID();
    Map<String, Object> body = issueBody(holder, key);
    body.put("issuerId", "https://evil.example/issuers/1");
    assertThatThrownBy(() -> issueRaw(issuer, key, body))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void outOfScopeTypeIsRejected() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "neg-scope", Set.of("ISSUER_OPS"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String key = "neg-scope-" + UUID.randomUUID();
    Map<String, Object> body = issueBody(holder, key);
    body.put("vct", "https://sovra.example/vct/passport/1");
    assertThatThrownBy(() -> issueRaw(issuer, key, body))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void extraClaimIsRejected() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "neg-claim", Set.of("ISSUER_OPS"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String key = "neg-claim-" + UUID.randomUUID();
    Map<String, Object> body = issueBody(holder, key);
    body.put("claims", Map.of("adultOver18", Boolean.TRUE, "ssn", "000-00-0000"));
    assertThatThrownBy(() -> issueRaw(issuer, key, body))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    Map<String, Object> body2 = issueBody(holder, "neg-claim2-" + UUID.randomUUID());
    body2.put("claims", Map.of("adultOver18", Boolean.FALSE));
    Map<String, Object> frozen = body2;
    String key2 = "neg-claim2-" + UUID.randomUUID();
    body2.put("holderProof",
        IssuanceFixtures.proof(holder, key2, IssuanceFixtures.ADULT_VCT, mapper));
    assertThatThrownBy(() -> issueRaw(issuer, key2, frozen))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void proofFromAnotherKeyIsRejected() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "neg-pop", Set.of("ISSUER_OPS"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    IssuanceFixtures.HolderKeys attacker = IssuanceFixtures.generateHolder(mapper);
    String key = "neg-pop-" + UUID.randomUUID();
    Map<String, Object> body = issueBody(holder, key);
    body.put("holderProof",
        IssuanceFixtures.proof(attacker, key, IssuanceFixtures.ADULT_VCT, mapper));
    assertThatThrownBy(() -> issueRaw(issuer, key, body))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void proofForAnotherRequestIsRejected() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "neg-pop2", Set.of("ISSUER_OPS"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String key = "neg-pop2-" + UUID.randomUUID();
    Map<String, Object> body = issueBody(holder, key);
    body.put("holderProof",
        IssuanceFixtures.proof(holder, "different-key", IssuanceFixtures.ADULT_VCT, mapper));
    assertThatThrownBy(() -> issueRaw(issuer, key, body))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void malformedHolderKeyIsRejected() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "neg-jwk", Set.of("ISSUER_OPS"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String key = "neg-jwk-" + UUID.randomUUID();
    Map<String, Object> body = issueBody(holder, key);
    body.put("holderJwk", Map.of("kty", "RSA", "n", "x", "e", "AQAB"));
    assertThatThrownBy(() -> issueRaw(issuer, key, body))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void malformedIdempotencyKeyIsRejected() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "neg-idem", Set.of("ISSUER_OPS"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    Map<String, Object> body = issueBody(holder, "ok-key");
    assertThatThrownBy(() -> issueRaw(issuer, "bad key!", body))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    assertThatThrownBy(
            () -> client.post().uri("/api/issuance/credentials")
                .headers(issuer.headers())
                .contentType(MediaType.APPLICATION_JSON).body(body)
                .retrieve().toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void validityOutsideRangeIsRejected() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "neg-exp", Set.of("ISSUER_OPS"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String pastKey = "neg-past-" + UUID.randomUUID();
    Map<String, Object> past = issueBody(holder, pastKey);
    past.put("expiresAt", Instant.now().minusSeconds(60).toString());
    assertThatThrownBy(() -> issueRaw(issuer, pastKey, past))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    String farKey = "neg-far-" + UUID.randomUUID();
    Map<String, Object> far = issueBody(holder, farKey);
    far.put("expiresAt", Instant.now().plus(java.time.Duration.ofDays(367)).toString());
    assertThatThrownBy(() -> issueRaw(issuer, farKey, far))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void sameKeyDifferentRequestConflicts() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "neg-422", Set.of("ISSUER_OPS"));
    IssuanceFixtures.HolderKeys first = IssuanceFixtures.generateHolder(mapper);
    IssuanceFixtures.HolderKeys second = IssuanceFixtures.generateHolder(mapper);
    String key = "neg-422-" + UUID.randomUUID();
    issueRaw(issuer, key, issueBody(first, key));
    assertThatThrownBy(() -> issueRaw(issuer, key, issueBody(second, key)))
        .isInstanceOf(HttpClientErrorException.UnprocessableContent.class);
  }

  @Test
  @SuppressWarnings("unchecked")
  void expiredKeyMayBeReusedForANewCredential() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "neg-reuse", Set.of("ISSUER_OPS"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String key = "neg-reuse-" + UUID.randomUUID();
    Map<String, Object> first =
        mapper.readValue(issueRaw(issuer, key, issueBody(holder, key)), Map.class);
    owner.update(
        "UPDATE issuance_idempotency SET expires_at = now() - INTERVAL '1 second'"
            + " WHERE tenant_id = ? AND idempotency_key = ?",
        issuer.tenantId(), key);
    Map<String, Object> second =
        mapper.readValue(issueRaw(issuer, key, issueBody(holder, key)), Map.class);
    assertThat(second.get("credentialId")).isNotEqualTo(first.get("credentialId"));
    assertThat(second.get("artifact")).isNotEqualTo(first.get("artifact"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void crossTenantCredentialIsNotFound() throws Exception {
    TestAccount issuerA = TestAccounts.create(owner, "neg-tenant-a", Set.of("ISSUER_OPS"));
    TestAccount issuerB =
        TestAccounts.create(owner, "neg-tenant-b", Set.of("ISSUER_OPS", "TENANT_MEMBER"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String key = "neg-tenant-" + UUID.randomUUID();
    Map<String, Object> response =
        mapper.readValue(issueRaw(issuerA, key, issueBody(holder, key)), Map.class);
    String id = response.get("credentialId").toString();
    assertThatThrownBy(
            () -> client.get().uri("/api/issuance/credentials/" + id)
                .headers(issuerB.headers()).retrieve().toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.NotFound.class)
        .satisfies(
            e -> assertThat(((HttpClientErrorException) e).getResponseBodyAsString()).isEmpty());
    Map<String, Object> status =
        client.get().uri("/api/issuance/credentials/" + id + "/status")
            .headers(issuerB.headers()).retrieve().body(Map.class);
    assertThat(status).isNotNull();
    assertThat(status.get("status")).isEqualTo("UNKNOWN");
    assertThatThrownBy(
            () -> client.post().uri("/api/issuance/credentials/" + id + "/revoke")
                .headers(issuerB.headers()).retrieve().toBodilessEntity())
        .isInstanceOf(HttpClientErrorException.NotFound.class);
  }

  @Test
  void revokedRegistryKeyRefusesToSign() {
    owner.update(
        "UPDATE issuer_signing_key SET status = 'REVOKED'"
            + " WHERE issuer_id = ? AND key_id = ? AND key_version = 1",
        IssuanceFixtures.ISSUER_ID, "synth-1");
    try {
      assertThatThrownBy(
              () -> signer.sign(new KeyRef(IssuanceFixtures.ISSUER_ID, "synth-1", 1),
                  "payload".getBytes(), "issuer=" + IssuanceFixtures.ISSUER_ID))
          .isInstanceOf(SigningRefusedException.class);
    } finally {
      owner.update(
          "UPDATE issuer_signing_key SET status = 'ACTIVE'"
              + " WHERE issuer_id = ? AND key_id = ? AND key_version = 1",
          IssuanceFixtures.ISSUER_ID, "synth-1");
    }
  }

  @Test
  void selfRegisteredKeyCannotSign() {
    owner.update(
        "INSERT INTO issuer_signing_key (issuer_id, key_id, key_version, public_key_jwk, status)"
            + " VALUES (?, 'attacker-key', 1, '{\"kty\":\"EC\"}', 'ACTIVE')",
        IssuanceFixtures.ISSUER_ID);
    try {
      assertThatThrownBy(
              () -> signer.sign(new KeyRef(IssuanceFixtures.ISSUER_ID, "attacker-key", 1),
                  "payload".getBytes(), "issuer=" + IssuanceFixtures.ISSUER_ID))
          .isInstanceOf(SigningRefusedException.class);
    } finally {
      owner.update(
          "DELETE FROM issuer_signing_key WHERE issuer_id = ? AND key_id = 'attacker-key'",
          IssuanceFixtures.ISSUER_ID);
    }
  }

  @Test
  void mismatchedCallContextRefusesToSign() {
    assertThatThrownBy(
            () -> signer.sign(new KeyRef(IssuanceFixtures.ISSUER_ID, "synth-1", 1),
                "payload".getBytes(), "issuer=https://evil.example/x"))
        .isInstanceOf(SigningRefusedException.class);
  }

  @Test
  void auditOutageFailsIssuanceAtomically() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "neg-audit", Set.of("ISSUER_OPS"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String key = "neg-audit-" + UUID.randomUUID();
    int before =
        owner.queryForObject("SELECT COUNT(*) FROM credential_artifact", Integer.class);
    owner.update("REVOKE INSERT ON audit_event FROM sovra_app");
    try {
      assertThatThrownBy(() -> issueRaw(issuer, key, issueBody(holder, key)))
          .isInstanceOf(HttpServerErrorException.InternalServerError.class);
    } finally {
      owner.update("GRANT INSERT ON audit_event TO sovra_app");
    }
    // The credential, idempotency record, and audit row commit together:
    // no evidence, no issuance, no half-written retry state.
    int after = owner.queryForObject("SELECT COUNT(*) FROM credential_artifact", Integer.class);
    assertThat(after).isEqualTo(before);
    int mappings =
        owner.queryForObject(
            "SELECT COUNT(*) FROM issuance_idempotency WHERE tenant_id = ? AND idempotency_key = ?",
            Integer.class, issuer.tenantId(), key);
    assertThat(mappings).isZero();
  }

  @Test
  void kmsSignerFailsLoudly() {
    assertThatThrownBy(() -> new KmsSigner().sign(
            new KeyRef("i", "k", 1), new byte[0], "issuer=i"))
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void signerExposesNoPrivateKeyAccessor() {
    for (Method method : LocalDevSigner.class.getDeclaredMethods()) {
      if (Modifier.isPublic(method.getModifiers())) {
        assertThat(method.getReturnType().getName())
            .as("public method " + method.getName())
            .doesNotContain("PrivateKey");
      }
    }
  }

  @Test
  void storedKeysCarryNoPrivateMaterial() {
    List<String> jwks =
        owner.query("SELECT public_key_jwk::text FROM issuer_signing_key",
            (rs, row) -> rs.getString(1));
    assertThat(jwks).isNotEmpty();
    for (String jwk : jwks) {
      assertThat(jwk).doesNotContain("\"d\"");
    }
    List<String> registry =
        owner.query("SELECT public_key_jwk::text FROM issuer_record",
            (rs, row) -> rs.getString(1));
    for (String jwk : registry) {
      assertThat(jwk).doesNotContain("\"d\"");
    }
  }

  @Test
  void keyRefRoundTrips() {
    KeyRef ref = new KeyRef(IssuanceFixtures.ISSUER_ID, "synth-1", 1);
    assertThat(KeyRef.decode(ref.encode())).isEqualTo(ref);
    assertThatThrownBy(() -> KeyRef.decode("nope"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new KeyRef("i", "k", 0))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
