package dev.sovra.issuance;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.trust.TrustService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * End-to-end issuance: signed artifacts, replays, revocation, rotation.
 * Boots as the least-privilege role, like production, so row-level
 * security applies to every read below.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class IssuanceFlowTests extends SovraAppRoleBase {

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

  @Test
  @SuppressWarnings("unchecked")
  void issueReturnsVerifiableArtifactAndReplaysByteForByte() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "flow-issuer", Set.of("ISSUER_OPS"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String key = "flow-" + UUID.randomUUID();

    // A retry resends the same bytes; only then is the replay byte-identical.
    Map<String, Object> body = issueBody(holder, key);
    String first = issueRaw(issuer, key, body);
    String second = issueRaw(issuer, key, body);
    assertThat(second).isEqualTo(first);

    Map<String, Object> response = mapper.readValue(first, Map.class);
    assertThat(response).containsKeys("credentialId", "artifact", "status", "expiresAt",
        "trustSnapshot");
    assertThat(response.get("status")).isEqualTo("VALID");

    String jwks = client.get().uri("/api/issuance/jwks.json").retrieve().body(String.class);
    IssuanceFixtures.VerifiedArtifact verified =
        IssuanceFixtures.verify(response.get("artifact").toString(), jwks, mapper);
    assertThat(verified.header().get("alg").asString()).isEqualTo("ES256");
    assertThat(verified.header().get("kid").asString()).isEqualTo("synth-1");
    assertThat(verified.claims().get("iss").asString()).isEqualTo(IssuanceFixtures.ISSUER_ID);
    assertThat(verified.claims().get("vct").asString()).isEqualTo(IssuanceFixtures.ADULT_VCT);
    assertThat(verified.claims().get("jti").asString())
        .isEqualTo(response.get("credentialId").toString());
    assertThat(verified.claims().get("sub").asString())
        .isEqualTo(IssuanceFixtures.thumbprint(holder));
    assertThat(verified.claims().get("claims").get("adultOver18").asBoolean()).isTrue();
    assertThat(verified.claims().get("synthetic").asBoolean()).isTrue();

    Map<String, Object> metadata =
        client.get().uri("/api/issuance/credentials/" + response.get("credentialId"))
            .headers(issuer.headers()).retrieve().body(Map.class);
    assertThat(metadata).isNotNull();
    assertThat(metadata.get("status")).isEqualTo("VALID");
    assertThat(metadata.keySet()).doesNotContain("artifact", "holderThumbprint");

    Map<String, Object> status =
        client.get().uri("/api/issuance/credentials/" + response.get("credentialId") + "/status")
            .headers(issuer.headers()).retrieve().body(Map.class);
    assertThat(status).isNotNull();
    assertThat(status.get("status")).isEqualTo("VALID");

    Map<String, Object> audit = TestAccounts.auditRow(owner, "ISSUE_CREDENTIAL");
    assertThat(audit.get("decision")).isEqualTo("PERMIT");
    assertThat(audit.get("detail").toString()).contains(response.get("credentialId").toString());
  }

  @Test
  @SuppressWarnings("unchecked")
  void concurrentIssuanceWithOneKeyCommitsOneCredential() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "race-issuer", Set.of("ISSUER_OPS"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String key = "race-" + UUID.randomUUID();
    Map<String, Object> body = issueBody(holder, key);

    int threads = 8;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    CountDownLatch gate = new CountDownLatch(1);
    try {
      List<Future<String>> futures = new ArrayList<>();
      for (int i = 0; i < threads; i++) {
        futures.add(pool.submit(() -> {
          gate.await(10, TimeUnit.SECONDS);
          return issueRaw(issuer, key, body);
        }));
      }
      gate.countDown();
      List<String> responses = new ArrayList<>();
      for (Future<String> future : futures) {
        responses.add(future.get(60, TimeUnit.SECONDS));
      }
      // Every racer saw the same committed issuance; the losers rolled
      // back to the savepoint and reconciled against the winner's row
      // instead of dying on an aborted transaction.
      assertThat(responses).allSatisfy(
          response -> assertThat(response).isEqualTo(responses.get(0)));
      Map<String, Object> response = mapper.readValue(responses.get(0), Map.class);
      assertThat(response.get("status")).isEqualTo("VALID");
    } finally {
      pool.shutdownNow();
    }
    Integer credentials = owner.queryForObject(
        "SELECT COUNT(*) FROM credential_artifact WHERE tenant_id = ?", Integer.class,
        issuer.tenantId());
    assertThat(credentials).isEqualTo(1);
    Integer mappings = owner.queryForObject(
        "SELECT COUNT(*) FROM issuance_idempotency WHERE tenant_id = ? AND idempotency_key = ?",
        Integer.class, issuer.tenantId(), key);
    assertThat(mappings).isEqualTo(1);
  }

  @Test
  void tamperedArtifactFailsVerification() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "tamper-issuer", Set.of("ISSUER_OPS"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String key = "tamper-" + UUID.randomUUID();
    JsonNode response = mapper.readTree(issueRaw(issuer, key, issueBody(holder, key)));
    String artifact = response.get("artifact").asString();
    String jwks = client.get().uri("/api/issuance/jwks.json").retrieve().body(String.class);

    String[] parts = artifact.split("\\.", -1);
    char flipped = parts[1].charAt(10) == 'A' ? 'B' : 'A';
    String tampered = parts[0] + "." + parts[1].substring(0, 10) + flipped
        + parts[1].substring(11) + "." + parts[2];
    try {
      IssuanceFixtures.verify(tampered, jwks, mapper);
      assertThat(false).as("tampered artifact must not verify").isTrue();
    } catch (Exception expected) {
      assertThat(expected).isNotNull();
    }
  }

  @Test
  void jwksIsPublicWithoutPrivateMaterial() {
    String jwks = client.get().uri("/api/issuance/jwks.json").retrieve().body(String.class);
    assertThat(jwks).isNotNull();
    assertThat(jwks).contains("\"kid\":\"synth-1\"");
    assertThat(jwks).doesNotContain("\"d\"");
  }

  @Test
  @SuppressWarnings("unchecked")
  void revokeIsTerminalButSignatureStaysVerifiable() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "revoke-issuer", Set.of("ISSUER_OPS"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String key = "revoke-" + UUID.randomUUID();
    Map<String, Object> response =
        mapper.readValue(issueRaw(issuer, key, issueBody(holder, key)), Map.class);
    String id = response.get("credentialId").toString();

    Map<String, Object> revoked =
        client.post().uri("/api/issuance/credentials/" + id + "/revoke")
            .headers(issuer.headers()).retrieve().body(Map.class);
    assertThat(revoked).isNotNull();
    assertThat(revoked.get("status")).isEqualTo("REVOKED");

    Map<String, Object> again =
        client.post().uri("/api/issuance/credentials/" + id + "/revoke")
            .headers(issuer.headers()).retrieve().body(Map.class);
    assertThat(again).isNotNull();
    assertThat(again.get("status")).isEqualTo("REVOKED");

    Map<String, Object> status =
        client.get().uri("/api/issuance/credentials/" + id + "/status")
            .headers(issuer.headers()).retrieve().body(Map.class);
    assertThat(status).isNotNull();
    assertThat(status.get("status")).isEqualTo("REVOKED");

    // Revocation is status, not signature: verifiers must check status.
    String jwks = client.get().uri("/api/issuance/jwks.json").retrieve().body(String.class);
    IssuanceFixtures.verify(response.get("artifact").toString(), jwks, mapper);
  }

  @Test
  @SuppressWarnings("unchecked")
  void rotationMovesIssuanceToTheNewSnapshot() throws Exception {
    long before = IssuanceFixtures.ensureSyntheticIssuer(owner, trust, mapper);
    TestAccount maker = TestAccounts.create(owner, "rot-maker", Set.of("TRUST_ADMIN"));
    TestAccount checker = TestAccounts.create(owner, "rot-checker", Set.of("TRUST_ADMIN"));
    Map<String, Object> genesis =
        owner.queryForMap(
            "SELECT issuer_id, display_name, scope, credential_types, key_id, public_key_jwk"
                + " FROM issuer_record WHERE snapshot_version ="
                + " (SELECT MIN(snapshot_version) FROM trust_snapshot_activation)"
                + " AND issuer_id = ?",
            IssuanceFixtures.ISSUER_ID);
    Instant now = Instant.now();
    var input =
        new TrustService.ProposalInput(
            List.of(
                new TrustService.IssuerInput(
                    (String) genesis.get("issuer_id"),
                    "Synthetic rotated",
                    (String) genesis.get("scope"),
                    List.of((String[]) ((java.sql.Array) genesis.get("credential_types"))
                        .getArray()),
                    (String) genesis.get("key_id"),
                    1,
                    mapper.readTree(String.valueOf(genesis.get("public_key_jwk"))),
                    now.minusSeconds(60),
                    now.plus(java.time.Duration.ofDays(3650)),
                    "ACTIVE")),
            List.of());
    dev.sovra.tenancy.TenantContext.set(IssuanceFixtures.asPrincipal(maker));
    TrustService.ProposalResult result;
    try {
      result = trust.propose(IssuanceFixtures.asPrincipal(maker), input, "test rotation");
    } finally {
      dev.sovra.tenancy.TenantContext.clear();
    }
    dev.sovra.tenancy.TenantContext.set(IssuanceFixtures.asPrincipal(checker));
    try {
      trust.approve(IssuanceFixtures.asPrincipal(checker), result.proposalId());
      trust.activate(IssuanceFixtures.asPrincipal(checker), result.version());
    } finally {
      dev.sovra.tenancy.TenantContext.clear();
    }
    assertThat(result.version()).isGreaterThan(before);

    TestAccount issuer = TestAccounts.create(owner, "rot-issuer", Set.of("ISSUER_OPS"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String key = "rot-" + UUID.randomUUID();
    Map<String, Object> response =
        mapper.readValue(issueRaw(issuer, key, issueBody(holder, key)), Map.class);
    assertThat(((Number) response.get("trustSnapshot")).longValue()).isEqualTo(result.version());
  }
}
