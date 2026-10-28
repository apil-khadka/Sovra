package dev.sovra.trust;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.consent.ConsentFixtures;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.verification.VerificationFixtures;
import dev.sovra.verification.VerificationFixtures.Stage;
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
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Issuer key rotation and compromise lifecycle (SOV-012, FR-23, SR-29).
 * Registration publishes a key version but never widens trust — only a
 * two-person snapshot activation authorizes it — and revocation is a
 * terminal row that signing, issuance, and verification honor live.
 * Boots as the least-privilege role, like production.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class IssuerKeyLifecycleTests extends SovraAppRoleBase {

  static final String ROT_ISSUER = "https://sovra.example/issuers/rot-1";

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

  private static String keyId(String tag) {
    return tag + "-" + UUID.randomUUID().toString().substring(0, 8);
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> register(TestAccount admin, Map<String, Object> body) {
    return client
        .post()
        .uri("/api/trust/keys")
        .headers(admin.headers())
        .contentType(MediaType.APPLICATION_JSON)
        .body(body)
        .retrieve()
        .body(Map.class);
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> revoke(TestAccount admin, Map<String, Object> body) {
    return client
        .post()
        .uri("/api/trust/keys/revoke")
        .headers(admin.headers())
        .contentType(MediaType.APPLICATION_JSON)
        .body(body)
        .retrieve()
        .body(Map.class);
  }

  private Map<String, Object> registerBody(String issuerId, String keyId, int version,
      Map<String, Object> jwk) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("issuerId", issuerId);
    body.put("keyId", keyId);
    body.put("keyVersion", version);
    body.put("publicKeyJwk", jwk);
    return body;
  }

  private Map<String, Object> revokeBody(String issuerId, String keyId, int version,
      String reason) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("issuerId", issuerId);
    body.put("keyId", keyId);
    body.put("keyVersion", version);
    body.put("reason", reason);
    return body;
  }

  private void deleteKey(String issuerId, String keyId, int version) {
    owner.update(
        "DELETE FROM issuer_key_revocation WHERE issuer_id = ? AND key_id = ? AND key_version = ?",
        issuerId, keyId, version);
    owner.update(
        "DELETE FROM issuer_signing_key WHERE issuer_id = ? AND key_id = ? AND key_version = ?",
        issuerId, keyId, version);
  }

  /** Current synth-issuer row as proposal JSON, so activations preserve it. */
  private Map<String, Object> synthIssuerJson() {
    TrustService.SnapshotView current = trust.currentSnapshot().orElseThrow();
    TrustService.IssuerView synth =
        current.issuers().stream()
            .filter(i -> IssuanceFixtures.ISSUER_ID.equals(i.issuerId()))
            .findFirst()
            .orElseThrow();
    Map<String, Object> json = new LinkedHashMap<>();
    json.put("issuerId", synth.issuerId());
    json.put("displayName", synth.displayName());
    json.put("scope", synth.scope());
    json.put("credentialTypes", synth.credentialTypes());
    json.put("keyId", synth.keyId());
    json.put("keyVersion", synth.keyVersion());
    json.put("publicKeyJwk", mapper.convertValue(synth.publicKeyJwk(), Map.class));
    json.put("validFrom", synth.validFrom().toString());
    json.put("validThrough", synth.validThrough().toString());
    json.put("status", synth.status());
    return json;
  }

  @SuppressWarnings("unchecked")
  private long activateIssuers(TestAccount maker, TestAccount checker,
      List<Map<String, Object>> issuers) {
    Map<String, Object> created =
        client
            .post()
            .uri("/api/trust/proposals")
            .headers(maker.headers())
            .contentType(MediaType.APPLICATION_JSON)
            .body(Map.of("issuers", issuers, "policies", List.of(), "note", "test: key lifecycle"))
            .retrieve()
            .body(Map.class);
    assertThat(created).isNotNull();
    long version = Long.parseLong(created.get("version").toString());
    client
        .post()
        .uri("/api/trust/proposals/" + created.get("proposalId") + "/approve")
        .headers(checker.headers())
        .retrieve()
        .toBodilessEntity();
    client
        .post()
        .uri("/api/trust/snapshots/" + version + "/activate")
        .headers(checker.headers())
        .retrieve()
        .toBodilessEntity();
    return version;
  }

  @Test
  void registrationAloneNeverWidensTrust() throws Exception {
    TestAccount admin = TestAccounts.create(owner, "key-admin", Set.of("TRUST_ADMIN"));
    String kid = keyId("rot-k");
    Map<String, Object> jwk = TrustFlowTests.p256Jwk(kid);
    try {
      Map<String, Object> view =
          register(admin, registerBody(ROT_ISSUER, kid, 1, jwk));
      assertThat(view).isNotNull();
      assertThat(view.get("status")).isEqualTo("ACTIVE");
      assertThat(((Number) view.get("keyVersion")).intValue()).isEqualTo(1);

      // The registry holds the key, but no snapshot authorizes it:
      // issuance for the new issuer is still untrusted, and the
      // published snapshot and JWKS do not name it.
      TestAccount issuer = TestAccounts.create(owner, "rot-issuer", Set.of("ISSUER_OPS"));
      IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
      String idem = "rot-untrusted-" + UUID.randomUUID();
      Map<String, Object> body = new LinkedHashMap<>();
      body.put("issuerId", ROT_ISSUER);
      body.put("vct", IssuanceFixtures.ADULT_VCT);
      body.put("holderJwk", mapper.convertValue(holder.jwk(), Map.class));
      body.put("holderProof", IssuanceFixtures.proof(holder, idem, IssuanceFixtures.ADULT_VCT, mapper));
      body.put("claims", Map.of("adultOver18", Boolean.TRUE));
      body.put("expiresAt", Instant.now().plusSeconds(3600).toString());
      assertThatThrownBy(
              () ->
                  client
                      .post()
                      .uri("/api/issuance/credentials")
                      .headers(
                          h -> {
                            issuer.headers().accept(h);
                            h.set("Idempotency-Key", idem);
                          })
                      .contentType(MediaType.APPLICATION_JSON)
                      .body(body)
                      .retrieve()
                      .body(String.class))
          .isInstanceOf(HttpClientErrorException.BadRequest.class);

      Map<String, Object> audit =
          owner.queryForMap(
              "SELECT * FROM audit_event WHERE action = 'REGISTER_ISSUER_KEY'"
                  + " ORDER BY occurred_at DESC LIMIT 1");
      assertThat(audit.get("decision")).isEqualTo("PERMIT");
      assertThat(audit.get("detail").toString()).contains(kid);
    } finally {
      deleteKey(ROT_ISSUER, kid, 1);
    }
  }

  @Test
  void identicalReregistrationIsIdempotent() {
    TestAccount admin = TestAccounts.create(owner, "key-idem", Set.of("TRUST_ADMIN"));
    String kid = keyId("idem-k");
    Map<String, Object> jwk = TrustFlowTests.p256Jwk(kid);
    try {
      Map<String, Object> first = register(admin, registerBody(ROT_ISSUER, kid, 1, jwk));
      Map<String, Object> second = register(admin, registerBody(ROT_ISSUER, kid, 1, jwk));
      assertThat(first.get("status")).isEqualTo("ACTIVE");
      assertThat(second.get("status")).isEqualTo("ACTIVE");
      Integer rows =
          owner.queryForObject(
              "SELECT COUNT(*) FROM issuer_signing_key WHERE issuer_id = ? AND key_id = ?",
              Integer.class, ROT_ISSUER, kid);
      assertThat(rows).isEqualTo(1);
    } finally {
      deleteKey(ROT_ISSUER, kid, 1);
    }
  }

  @Test
  void conflictingReregistrationIsRejected() {
    TestAccount admin = TestAccounts.create(owner, "key-conf", Set.of("TRUST_ADMIN"));
    String kid = keyId("conf-k");
    try {
      register(admin, registerBody(ROT_ISSUER, kid, 1, TrustFlowTests.p256Jwk(kid)));
      Map<String, Object> other = new LinkedHashMap<>(TrustFlowTests.p256Jwk(kid));
      other.put("x", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
      assertThatThrownBy(() -> register(admin, registerBody(ROT_ISSUER, kid, 1, other)))
          .isInstanceOf(HttpClientErrorException.Conflict.class)
          .satisfies(
              e -> assertThat(((HttpClientErrorException) e).getResponseBodyAsString())
                  .contains("issuer_key_conflict"));
      // First writer wins: the stored key is unchanged.
      String stored =
          owner.queryForObject(
              "SELECT public_key_jwk::text FROM issuer_signing_key"
                  + " WHERE issuer_id = ? AND key_id = ? AND key_version = 1",
              String.class, ROT_ISSUER, kid);
      assertThat(stored).contains(kid);
      assertThat(stored).doesNotContain("AAAAAAAA");
    } finally {
      deleteKey(ROT_ISSUER, kid, 1);
    }
  }

  @Test
  void registrationRejectsBadKeys() {
    TestAccount admin = TestAccounts.create(owner, "key-bad", Set.of("TRUST_ADMIN"));
    String kid = keyId("bad-k");
    // kid must equal the key record id.
    assertThatThrownBy(
            () -> register(admin,
                registerBody(ROT_ISSUER, kid, 1, TrustFlowTests.p256Jwk("other-kid"))))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    // Private material is never accepted.
    Map<String, Object> withD = new LinkedHashMap<>(TrustFlowTests.p256Jwk(kid));
    withD.put("d", "private");
    assertThatThrownBy(
            () -> register(admin, registerBody(ROT_ISSUER, kid, 1, withD)))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    // Versions start at 1.
    assertThatThrownBy(
            () -> register(admin,
                registerBody(ROT_ISSUER, kid, 0, TrustFlowTests.p256Jwk(kid))))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    Integer rows =
        owner.queryForObject(
            "SELECT COUNT(*) FROM issuer_signing_key WHERE issuer_id = ? AND key_id = ?",
            Integer.class, ROT_ISSUER, kid);
    assertThat(rows).isZero();
  }

  @Test
  void revocationIsTerminalAndIdempotent() {
    TestAccount admin = TestAccounts.create(owner, "key-rev", Set.of("TRUST_ADMIN"));
    String kid = keyId("rev-k");
    try {
      register(admin, registerBody(ROT_ISSUER, kid, 1, TrustFlowTests.p256Jwk(kid)));
      // Unknown identities are an empty 404, not a leak.
      assertThatThrownBy(
              () -> revoke(admin, revokeBody(ROT_ISSUER, "missing-k", 1, "compromised")))
          .isInstanceOf(HttpClientErrorException.NotFound.class)
          .satisfies(
              e -> assertThat(((HttpClientErrorException) e).getResponseBodyAsString()).isEmpty());
      // A reason is required containment evidence.
      assertThatThrownBy(
              () -> revoke(admin, revokeBody(ROT_ISSUER, kid, 1, "  ")))
          .isInstanceOf(HttpClientErrorException.BadRequest.class);

      Map<String, Object> first =
          revoke(admin, revokeBody(ROT_ISSUER, kid, 1, "compromised HSM slot 3"));
      assertThat(first.get("status")).isEqualTo("REVOKED");
      assertThat(first.get("revokedAt")).isNotNull();
      Map<String, Object> second =
          revoke(admin, revokeBody(ROT_ISSUER, kid, 1, "compromised HSM slot 3"));
      assertThat(second.get("revokedAt")).isEqualTo(first.get("revokedAt"));
      Integer rows =
          owner.queryForObject(
              "SELECT COUNT(*) FROM issuer_key_revocation WHERE issuer_id = ? AND key_id = ?",
              Integer.class, ROT_ISSUER, kid);
      assertThat(rows).isEqualTo(1);

      Map<String, Object> audit =
          owner.queryForMap(
              "SELECT * FROM audit_event WHERE action = 'REVOKE_ISSUER_KEY'"
                  + " ORDER BY occurred_at DESC LIMIT 1");
      assertThat(audit.get("decision")).isEqualTo("PERMIT");
      assertThat(audit.get("detail").toString()).contains("revoked_at");
    } finally {
      deleteKey(ROT_ISSUER, kid, 1);
    }
  }

  @Test
  void rotationAuthorizesOnlyThroughSnapshotActivation() {
    TestAccount maker = TestAccounts.create(owner, "rot-maker", Set.of("TRUST_ADMIN"));
    TestAccount checker = TestAccounts.create(owner, "rot-checker", Set.of("TRUST_ADMIN"));
    String kid = keyId("rot-k");
    try {
      register(maker, registerBody(ROT_ISSUER, kid, 1, TrustFlowTests.p256Jwk(kid)));
      Map<String, Object> rotated = new LinkedHashMap<>();
      rotated.put("issuerId", ROT_ISSUER);
      rotated.put("displayName", "Rotated test issuer");
      rotated.put("scope", "adult-status");
      rotated.put("credentialTypes", List.of(IssuanceFixtures.ADULT_VCT));
      rotated.put("keyId", kid);
      rotated.put("keyVersion", 1);
      rotated.put("publicKeyJwk", TrustFlowTests.p256Jwk(kid));
      rotated.put("validFrom", Instant.now().minusSeconds(60).toString());
      rotated.put("validThrough", Instant.now().plusSeconds(3600).toString());
      rotated.put("status", "ACTIVE");
      long version =
          activateIssuers(maker, checker, List.of(synthIssuerJson(), rotated));
      try {
        // The activation is the switch: the snapshot pins the exact new
        // key id and version, and federation metadata publishes it.
        TrustService.SnapshotView current = trust.currentSnapshot().orElseThrow();
        assertThat(current.version()).isEqualTo(version);
        TrustService.IssuerView pinned =
            current.issuers().stream()
                .filter(i -> ROT_ISSUER.equals(i.issuerId()))
                .findFirst()
                .orElseThrow();
        assertThat(pinned.keyId()).isEqualTo(kid);
        assertThat(pinned.keyVersion()).isEqualTo(1);
        String jwks = client.get().uri("/api/issuance/jwks.json").retrieve().body(String.class);
        assertThat(jwks).contains("\"kid\":\"" + kid + "\"");
      } finally {
        // Restore a synth-only snapshot: later tests share this container
        // and the JWKS key order is unspecified.
        activateIssuers(maker, checker, List.of(synthIssuerJson()));
      }
      // Registration without activation authorizes nothing: a proposal
      // pinning an unregistered version is shape-valid but that epoch
      // can never sign or issue while the registry lacks the key.
      Map<String, Object> unregistered = new LinkedHashMap<>(rotated);
      unregistered.put("keyVersion", 2);
      long ghost = activateIssuers(maker, checker, List.of(synthIssuerJson(), unregistered));
      try {
        TrustService.SnapshotView current = trust.currentSnapshot().orElseThrow();
        assertThat(current.version()).isEqualTo(ghost);
        assertThat(
                IssuerKeys.active(
                    new JdbcTemplate(ownerDataSource()), ROT_ISSUER, kid, 2))
            .isFalse();
      } finally {
        activateIssuers(maker, checker, List.of(synthIssuerJson()));
      }
    } finally {
      deleteKey(ROT_ISSUER, kid, 1);
    }
  }

  @Test
  void revokedKeysLeaveServingJwksWhileSnapshotsStand() {
    TestAccount maker = TestAccounts.create(owner, "jwks-maker", Set.of("TRUST_ADMIN"));
    TestAccount checker = TestAccounts.create(owner, "jwks-checker", Set.of("TRUST_ADMIN"));
    String kid = keyId("jwks-k");
    try {
      register(maker, registerBody(ROT_ISSUER, kid, 1, TrustFlowTests.p256Jwk(kid)));
      Map<String, Object> rotated = new LinkedHashMap<>();
      rotated.put("issuerId", ROT_ISSUER);
      rotated.put("displayName", "JWKS rotation test issuer");
      rotated.put("scope", "adult-status");
      rotated.put("credentialTypes", List.of(IssuanceFixtures.ADULT_VCT));
      rotated.put("keyId", kid);
      rotated.put("keyVersion", 1);
      rotated.put("publicKeyJwk", TrustFlowTests.p256Jwk(kid));
      rotated.put("validFrom", Instant.now().minusSeconds(60).toString());
      rotated.put("validThrough", Instant.now().plusSeconds(3600).toString());
      rotated.put("status", "ACTIVE");
      activateIssuers(maker, checker, List.of(synthIssuerJson(), rotated));
      try {
        String before =
            client.get().uri("/api/issuance/jwks.json").retrieve().body(String.class);
        assertThat(before).contains("\"kid\":\"" + kid + "\"");
        assertThat(before).contains("\"kid\":\"synth-1\"");

        revoke(checker, revokeBody(ROT_ISSUER, kid, 1, "JWKS serving drill"));

        // The serving set drops the revoked key while the unrevoked
        // rotation window keeps serving the synth key.
        String after =
            client.get().uri("/api/issuance/jwks.json").retrieve().body(String.class);
        assertThat(after).doesNotContain("\"kid\":\"" + kid + "\"");
        assertThat(after).contains("\"kid\":\"synth-1\"");

        // The snapshot itself is immutable history: it still pins the
        // key the revocation retired. Enforcement lives in the live
        // revocation check, not in rewriting the snapshot.
        TrustService.SnapshotView current = trust.currentSnapshot().orElseThrow();
        assertThat(
                current.issuers().stream()
                    .filter(i -> ROT_ISSUER.equals(i.issuerId()))
                    .map(TrustService.IssuerView::keyId)
                    .toList())
            .contains(kid);
      } finally {
        activateIssuers(maker, checker, List.of(synthIssuerJson()));
      }
    } finally {
      deleteKey(ROT_ISSUER, kid, 1);
    }
  }

  @Test
  void snapshotKeyVersionIsValidated() {
    TestAccount maker = TestAccounts.create(owner, "ver-maker", Set.of("TRUST_ADMIN"));
    Map<String, Object> issuer = new LinkedHashMap<>(TrustFlowTests.issuer("bad-ver-k"));
    issuer.put("keyVersion", 0);
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/trust/proposals")
                    .headers(maker.headers())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("issuers", List.of(issuer), "policies", List.of(), "note", "v"))
                    .retrieve()
                    .body(Map.class))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  @SuppressWarnings("unchecked")
  void revokedLiveKeyNarrowsIssuanceAndVerification() throws Exception {
    Stage stage = VerificationFixtures.approvedStage(client, owner, mapper, "live-rev");
    assertThat(IssuerKeys.active(
            new JdbcTemplate(ownerDataSource()),
            IssuanceFixtures.ISSUER_ID, "synth-1", 1))
        .isTrue();
    TestAccount admin = TestAccounts.create(owner, "live-admin", Set.of("TRUST_ADMIN"));
    Map<String, Object> revoked =
        revoke(admin,
            revokeBody(IssuanceFixtures.ISSUER_ID, "synth-1", 1, "SOV-012 live-path drill"));
    assertThat(revoked.get("status")).isEqualTo("REVOKED");
    try {
      // Issuance refuses: the snapshot still names the key, but the
      // live revocation row denies it.
      TestAccount issuer = TestAccounts.create(owner, "live-issuer", Set.of("ISSUER_OPS"));
      IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
      String idem = "live-rev-" + UUID.randomUUID();
      Map<String, Object> body = new LinkedHashMap<>();
      body.put("issuerId", IssuanceFixtures.ISSUER_ID);
      body.put("vct", IssuanceFixtures.ADULT_VCT);
      body.put("holderJwk", mapper.convertValue(holder.jwk(), Map.class));
      body.put("holderProof",
          IssuanceFixtures.proof(holder, idem, IssuanceFixtures.ADULT_VCT, mapper));
      body.put("claims", Map.of("adultOver18", Boolean.TRUE));
      body.put("expiresAt", Instant.now().plusSeconds(3600).toString());
      assertThatThrownBy(
              () ->
                  client
                      .post()
                      .uri("/api/issuance/credentials")
                      .headers(
                          h -> {
                            issuer.headers().accept(h);
                            h.set("Idempotency-Key", idem);
                          })
                      .contentType(MediaType.APPLICATION_JSON)
                      .body(body)
                      .retrieve()
                      .body(String.class))
          .isInstanceOf(HttpClientErrorException.BadRequest.class);

      // Verification rejects with the compromised key named in the
      // recorded evidence versions.
      Map<String, Object> decided =
          VerificationFixtures.verify(client, stage.rp(),
              VerificationFixtures.verifyBody(stage.holder(), stage.requestId(),
                  VerificationFixtures.nonce(), ConsentFixtures.AUDIENCE, mapper));
      assertThat(decided.get("outcome")).isEqualTo("REJECTED");
      assertThat(decided.get("reasonCode")).isEqualTo("ISSUER_KEY_INACTIVE");
      assertThat(decided.get("keyRef"))
          .isEqualTo(IssuanceFixtures.ISSUER_ID + ":synth-1:v1");
      assertThat(((Number) decided.get("statusVersion")).longValue()).isEqualTo(1);
      Map<String, Object> stored =
          VerificationFixtures.decision(client, stage.rp(), decided.get("decisionId").toString());
      assertThat(stored.get("keyRef")).isEqualTo(IssuanceFixtures.ISSUER_ID + ":synth-1:v1");
    } finally {
      owner.update(
          "DELETE FROM issuer_key_revocation WHERE issuer_id = ? AND key_id = 'synth-1'",
          IssuanceFixtures.ISSUER_ID);
    }
    // Containment lifted: the live path accepts again.
    Map<String, Object> retry =
        VerificationFixtures.verify(client, stage.rp(),
            VerificationFixtures.verifyBody(stage.holder(), stage.requestId(),
                VerificationFixtures.nonce(), ConsentFixtures.AUDIENCE, mapper));
    assertThat(retry.get("outcome")).isEqualTo("ACCEPTED");
  }

  @Test
  void concurrentRevokesConvergeOnOneInstant() throws Exception {
    TestAccount admin = TestAccounts.create(owner, "race-admin", Set.of("TRUST_ADMIN"));
    String kid = keyId("race-k");
    try {
      register(admin, registerBody(ROT_ISSUER, kid, 1, TrustFlowTests.p256Jwk(kid)));
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
                    return revoke(admin, revokeBody(ROT_ISSUER, kid, 1, "race drill"));
                  }));
        }
        gate.countDown();
        List<Map<String, Object>> views = new ArrayList<>();
        for (Future<Map<String, Object>> future : futures) {
          views.add(future.get(60, TimeUnit.SECONDS));
        }
        assertThat(views)
            .allSatisfy(v -> assertThat(v.get("status")).isEqualTo("REVOKED"));
        assertThat(views.stream().map(v -> v.get("revokedAt")).distinct().count()).isEqualTo(1);
      } finally {
        pool.shutdownNow();
      }
      Integer rows =
          owner.queryForObject(
              "SELECT COUNT(*) FROM issuer_key_revocation WHERE issuer_id = ? AND key_id = ?",
              Integer.class, ROT_ISSUER, kid);
      assertThat(rows).isEqualTo(1);
    } finally {
      deleteKey(ROT_ISSUER, kid, 1);
    }
  }

  @Test
  void wrongRolesAreDenied() {
    TestAccount ops = TestAccounts.create(owner, "key-ops", Set.of("ISSUER_OPS"));
    TestAccount planner = TestAccounts.create(owner, "key-planner", Set.of("PLANNER"));
    String kid = keyId("role-k");
    Map<String, Object> reg = registerBody(ROT_ISSUER, kid, 1, TrustFlowTests.p256Jwk(kid));
    Map<String, Object> rev = revokeBody(ROT_ISSUER, kid, 1, "no authority");
    assertThatThrownBy(() -> register(ops, reg))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(() -> revoke(ops, rev))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(() -> register(planner, reg))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    assertThatThrownBy(() -> revoke(planner, rev))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
    Integer rows =
        owner.queryForObject(
            "SELECT COUNT(*) FROM issuer_signing_key WHERE issuer_id = ? AND key_id = ?",
            Integer.class, ROT_ISSUER, kid);
    assertThat(rows).isZero();
  }

  @Test
  void anonymousCallsAreRejected() {
    Map<String, Object> reg =
        registerBody(ROT_ISSUER, keyId("anon-k"), 1, TrustFlowTests.p256Jwk("anon-k"));
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/trust/keys")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(reg)
                    .retrieve()
                    .body(String.class))
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
    assertThatThrownBy(
            () ->
                client
                    .post()
                    .uri("/api/trust/keys/revoke")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(revokeBody(ROT_ISSUER, "anon-k", 1, "x"))
                    .retrieve()
                    .body(String.class))
        .isInstanceOf(HttpClientErrorException.Unauthorized.class);
  }
}
