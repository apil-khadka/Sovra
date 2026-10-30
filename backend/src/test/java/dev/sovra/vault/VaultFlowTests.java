package dev.sovra.vault;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.HexFormat;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.RestClient;

/**
 * Vault happy paths (SOV-016): seal, grant, read, version, rotate,
 * revoke, delete, and concurrent writers.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class VaultFlowTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  @Autowired DataSource dataSource;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
  }

  @Test
  @SuppressWarnings("unchecked")
  void storeGrantReadRoundTrip() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "vault-issuer", Set.of("ISSUER_OPS"));
    TestAccount member = TestAccounts.createInTenant(
        owner, issuer.tenantId(), "vault-member", Set.of("TENANT_MEMBER"));
    byte[] content = "synthetic-id-image-bytes".getBytes(StandardCharsets.UTF_8);
    String pin = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));

    Map<String, Object> stored = post("/api/vault/objects", issuer.headers(), Map.of(
        "issuerId", "https://issuer.example/vault-1",
        "displayName", "synthetic doc",
        "purposes", List.of("enrollment-review", "verification-display"),
        "contentBase64", Base64.getEncoder().encodeToString(content),
        "contentSha256Hex", pin));
    String objectId = stored.get("objectId").toString();
    assertThat(stored.get("version")).isEqualTo(1);
    assertThat(stored.toString()).doesNotContain("contentBase64");

    Map<String, Object> meta =
        client.get().uri("/api/vault/objects/" + objectId).headers(issuer.headers())
            .retrieve().body(Map.class);
    assertThat(meta.get("issuerId")).isEqualTo("https://issuer.example/vault-1");
    List<Map<String, Object>> versions = (List<Map<String, Object>>) meta.get("versions");
    assertThat(versions).hasSize(1);
    assertThat(versions.get(0).get("kekVersion")).isEqualTo(1);
    assertThat(versions.get(0).get("contentSha256Hex")).isEqualTo(pin);
    assertThat(meta.toString()).doesNotContain("ciphertext", "wrappedDek", "wrapped_dek");

    Map<String, Object> granted = post("/api/vault/grants", issuer.headers(), Map.of(
        "objectId", objectId,
        "objectVersion", 1,
        "principalType", "service_account",
        "principalId", member.accountId().toString(),
        "purpose", "enrollment-review",
        "workload", "review-desk",
        "ttlSeconds", 3600));
    String grantId = granted.get("grantId").toString();
    assertThat(granted.get("revoked")).isEqualTo(Boolean.FALSE);

    Map<String, Object> read = post(
        "/api/vault/objects/" + objectId + "/versions/1/read", member.headers(), Map.of(
            "grantId", grantId, "purpose", "enrollment-review", "workload", "review-desk"));
    assertThat(read.get("contentSha256Hex")).isEqualTo(pin);
    assertThat(Base64.getDecoder().decode(read.get("contentBase64").toString()))
        .isEqualTo(content);
  }

  @Test
  @SuppressWarnings("unchecked")
  void versionsRotateAndOldDataStillReads() {
    TestAccount issuer = TestAccounts.create(owner, "vault-rot", Set.of("ISSUER_OPS", "TRUST_ADMIN"));
    String objectId = store(issuer, List.of("enrollment-review"), "v1-bytes");
    post("/api/vault/objects/" + objectId + "/versions", issuer.headers(), Map.of(
        "purposes", List.of("enrollment-review"),
        "contentBase64", base64("v2-bytes")));
    Map<String, Object> rotated = post("/api/vault/keys/rotate", issuer.headers(), Map.of());
    assertThat(rotated.get("kekVersion")).isEqualTo(2);
    Map<String, Object> third = post(
        "/api/vault/objects/" + objectId + "/versions", issuer.headers(), Map.of(
            "purposes", List.of("enrollment-review"),
            "contentBase64", base64("v3-bytes")));
    assertThat(third.get("version")).isEqualTo(3);

    Map<String, Object> meta =
        client.get().uri("/api/vault/objects/" + objectId).headers(issuer.headers())
            .retrieve().body(Map.class);
    List<Map<String, Object>> versions = (List<Map<String, Object>>) meta.get("versions");
    assertThat(versions.stream().map(v -> v.get("kekVersion")).toList())
        .containsExactly(1, 1, 2);

    // Every generation still opens under its own wrapping version.
    for (int version = 1; version <= 3; version++) {
      Map<String, Object> granted = post("/api/vault/grants", issuer.headers(), Map.of(
          "objectId", objectId,
          "objectVersion", version,
          "purpose", "enrollment-review",
          "workload", "review-desk",
          "ttlSeconds", 3600));
      Map<String, Object> read = post(
          "/api/vault/objects/" + objectId + "/versions/" + version + "/read",
          issuer.headers(), Map.of(
              "grantId", granted.get("grantId").toString(),
              "purpose", "enrollment-review",
              "workload", "review-desk"));
      assertThat(new String(
              Base64.getDecoder().decode(read.get("contentBase64").toString()),
              StandardCharsets.UTF_8))
          .isEqualTo("v" + version + "-bytes");
    }
  }

  @Test
  void revokeDeniesImmediately() {
    TestAccount issuer = TestAccounts.create(owner, "vault-rev", Set.of("ISSUER_OPS"));
    String objectId = store(issuer, List.of("enrollment-review"), "rev-bytes");
    Map<String, Object> granted = post("/api/vault/grants", issuer.headers(), Map.of(
        "objectId", objectId, "objectVersion", 1, "purpose", "enrollment-review",
        "workload", "review-desk", "ttlSeconds", 3600));
    String grantId = granted.get("grantId").toString();
    Map<String, Object> read = post(
        "/api/vault/objects/" + objectId + "/versions/1/read", issuer.headers(), Map.of(
            "grantId", grantId, "purpose", "enrollment-review", "workload", "review-desk"));
    assertThat(read.get("version")).isEqualTo(1);
    Map<String, Object> revoked =
        post("/api/vault/grants/" + grantId + "/revoke", issuer.headers(), Map.of());
    assertThat(revoked.get("revoked")).isEqualTo(Boolean.TRUE);
    org.assertj.core.api.Assertions.assertThatThrownBy(() -> post(
            "/api/vault/objects/" + objectId + "/versions/1/read", issuer.headers(), Map.of(
                "grantId", grantId, "purpose", "enrollment-review", "workload", "review-desk")))
        .isInstanceOf(org.springframework.web.client.HttpClientErrorException.Forbidden.class)
        .hasMessageContaining("GRANT_REVOKED");
  }

  @Test
  @SuppressWarnings("unchecked")
  void deleteVersionRefusesReads() {
    TestAccount admin =
        TestAccounts.create(owner, "vault-del", Set.of("ISSUER_OPS", "TRUST_ADMIN"));
    String objectId = store(admin, List.of("enrollment-review"), "del-bytes");
    Map<String, Object> granted = post("/api/vault/grants", admin.headers(), Map.of(
        "objectId", objectId, "objectVersion", 1, "purpose", "enrollment-review",
        "workload", "review-desk", "ttlSeconds", 3600));
    Map<String, Object> deleted = post(
        "/api/vault/objects/" + objectId + "/versions/1/delete", admin.headers(), Map.of());
    assertThat(deleted.get("status")).isEqualTo("DELETED");
    org.assertj.core.api.Assertions.assertThatThrownBy(() -> post(
            "/api/vault/objects/" + objectId + "/versions/1/read", admin.headers(), Map.of(
                "grantId", granted.get("grantId").toString(),
                "purpose", "enrollment-review", "workload", "review-desk")))
        .isInstanceOf(org.springframework.web.client.HttpClientErrorException.NotFound.class);
    Map<String, Object> again = post(
        "/api/vault/objects/" + objectId + "/versions/1/delete", admin.headers(), Map.of());
    assertThat(again.get("status")).isEqualTo("DELETED");
  }

  @Test
  @SuppressWarnings("unchecked")
  void concurrentVersionsAreDistinctAndAllOpen() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "vault-conc", Set.of("ISSUER_OPS"));
    String objectId = store(issuer, List.of("enrollment-review"), "genesis-bytes");
    int writers = 8;
    try (var pool = Executors.newFixedThreadPool(writers)) {
      List<Callable<Map<String, Object>>> jobs = new ArrayList<>();
      for (int i = 0; i < writers; i++) {
        int slot = i;
        jobs.add(() -> post(
            "/api/vault/objects/" + objectId + "/versions", issuer.headers(), Map.of(
                "purposes", List.of("enrollment-review"),
                "contentBase64", base64("concurrent-" + slot))));
      }
      List<Future<Map<String, Object>>> done = pool.invokeAll(jobs);
      Set<Object> versions = new HashSet<>();
      for (Future<Map<String, Object>> task : done) {
        versions.add(task.get().get("version"));
      }
      assertThat(versions).hasSize(writers);
    }
    // Every sealed row differs (fresh DEK + nonce per version) and opens.
    List<byte[]> raws = owner.query(
        "SELECT ciphertext FROM vault_object_version WHERE object_id = ? ORDER BY version",
        (rs, row) -> rs.getBytes(1), UUID.fromString(objectId));
    assertThat(raws).hasSize(writers + 1);
    assertThat(raws.stream().map(java.util.Arrays::toString).distinct().count())
        .isEqualTo((long) writers + 1);
    for (int version = 1; version <= writers + 1; version++) {
      Map<String, Object> granted = post("/api/vault/grants", issuer.headers(), Map.of(
          "objectId", objectId, "objectVersion", version, "purpose", "enrollment-review",
          "workload", "review-desk", "ttlSeconds", 3600));
      Map<String, Object> read = post(
          "/api/vault/objects/" + objectId + "/versions/" + version + "/read",
          issuer.headers(), Map.of(
              "grantId", granted.get("grantId").toString(),
              "purpose", "enrollment-review", "workload", "review-desk"));
      assertThat(read.get("contentBase64")).isNotNull();
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void purgeDestroysBytesAfterDelete() {
    TestAccount admin =
        TestAccounts.create(owner, "vault-purge", Set.of("ISSUER_OPS", "TRUST_ADMIN"));
    String objectId = store(admin, List.of("enrollment-review"), "purge-bytes");

    // Live versions refuse: delete first, purge second.
    org.assertj.core.api.Assertions.assertThatThrownBy(() -> post(
            "/api/vault/objects/" + objectId + "/versions/1/purge", admin.headers(), Map.of()))
        .isInstanceOf(org.springframework.web.client.HttpClientErrorException.Conflict.class);

    Map<String, Object> deleted = post(
        "/api/vault/objects/" + objectId + "/versions/1/delete", admin.headers(), Map.of());
    assertThat(deleted.get("status")).isEqualTo("DELETED");
    Map<String, Object> purged = post(
        "/api/vault/objects/" + objectId + "/versions/1/purge", admin.headers(), Map.of());
    assertThat(purged.get("status")).isEqualTo("PURGED");

    // Ciphertext and every key-nonce column are gone; the
    // tombstone (hash, standing) stays for audit.
    Map<String, Object> row = owner.queryForMap(
        "SELECT status, content_sha256, octet_length(wrapped_dek) AS dek,"
            + " octet_length(ciphertext) AS ct FROM vault_object_version"
            + " WHERE object_id = ? AND version = 1",
        UUID.fromString(objectId));
    assertThat(row.get("status")).isEqualTo("PURGED");
    assertThat(row.get("content_sha256")).isNotNull();
    assertThat(((Number) row.get("dek")).longValue()).isEqualTo(0);
    assertThat(((Number) row.get("ct")).longValue()).isEqualTo(0);

    // Repeats succeed; metadata keeps the PURGED tombstone.
    Map<String, Object> again = post(
        "/api/vault/objects/" + objectId + "/versions/1/purge", admin.headers(), Map.of());
    assertThat(again.get("status")).isEqualTo("PURGED");
    Map<String, Object> meta =
        client.get().uri("/api/vault/objects/" + objectId).headers(admin.headers())
            .retrieve().body(Map.class);
    assertThat(meta).isNotNull();
    List<Map<String, Object>> versions = (List<Map<String, Object>>) meta.get("versions");
    assertThat(versions).hasSize(1);
    assertThat(versions.get(0).get("status")).isEqualTo("PURGED");
  }

  @Test
  @SuppressWarnings("unchecked")
  void liveGrantBudgetCapsSixtyFourPerVersion() {
    TestAccount issuer = TestAccounts.create(owner, "vault-budget", Set.of("ISSUER_OPS"));
    String objectId = store(issuer, List.of("enrollment-review"), "budget-bytes");
    String firstGrant = null;
    for (int i = 0; i < 64; i++) {
      Map<String, Object> granted = post("/api/vault/grants", issuer.headers(), Map.of(
          "objectId", objectId, "objectVersion", 1, "purpose", "enrollment-review",
          "workload", "review-desk", "ttlSeconds", 3600));
      if (i == 0) {
        firstGrant = granted.get("grantId").toString();
      }
    }
    org.assertj.core.api.Assertions.assertThatThrownBy(() -> post(
            "/api/vault/grants", issuer.headers(), Map.of(
                "objectId", objectId, "objectVersion", 1, "purpose", "enrollment-review",
                "workload", "review-desk", "ttlSeconds", 3600)))
        .isInstanceOf(org.springframework.web.client.HttpClientErrorException.Conflict.class);
    // Revoking one frees exactly one slot.
    Map<String, Object> revoked = post(
        "/api/vault/grants/" + firstGrant + "/revoke", issuer.headers(), Map.of());
    assertThat(revoked).isNotNull();
    Map<String, Object> granted = post("/api/vault/grants", issuer.headers(), Map.of(
        "objectId", objectId, "objectVersion", 1, "purpose", "enrollment-review",
        "workload", "review-desk", "ttlSeconds", 3600));
    assertThat(granted.get("grantId")).isNotNull();
  }

  private String store(TestAccount issuer, List<String> purposes, String content) {
    Map<String, Object> stored = post("/api/vault/objects", issuer.headers(), Map.of(
        "issuerId", "https://issuer.example/vault-1",
        "purposes", purposes,
        "contentBase64", base64(content)));
    return stored.get("objectId").toString();
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> post(
      String uri, java.util.function.Consumer<org.springframework.http.HttpHeaders> headers,
      Map<String, Object> body) {
    return client.post().uri(uri).headers(headers).body(body).retrieve().body(Map.class);
  }

  private static String base64(String text) {
    return Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8));
  }

}
