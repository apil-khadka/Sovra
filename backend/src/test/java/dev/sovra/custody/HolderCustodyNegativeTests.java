package dev.sovra.custody;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.issuance.IssuanceFixtures;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Custody adversarial matrix (SOV-020, SEC-43, MC-09): report and
 * recovery authorization, proof binding, stale-case recovery,
 * double operations, tenant isolation, and the no-private-material
 * guarantee.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class HolderCustodyNegativeTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  @Autowired ObjectMapper mapper;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
  }

  @Test
  void reportAloneGrantsNothing() throws Exception {
    TestAccount ops = TestAccounts.create(owner, "cun-rep", Set.of("ISSUER_OPS"));
    Case Case = approvedCase(ops);
    // Reporting needs no holder proof — any operator may report —
    // but the report alone authorizes no recovery act.
    Map<String, Object> reported = post("/api/holder-keys/report", ops.headers(), Map.of(
        "thumbprint", IssuanceFixtures.thumbprint(Case.holder()), "reason", "loss"));
    assertThat(reported.get("recoveryId").toString()).isNotBlank();
    // Recovery without the fresh-key proof terminates.
    IssuanceFixtures.HolderKeys fresh = IssuanceFixtures.generateHolder(mapper);
    TestAccount admin = TestAccounts.createInTenant(
        owner, ops.tenantId(), "cun-rep-admin", Set.of("TRUST_ADMIN"));
    assertThatThrownBy(() -> post("/api/holder-keys/recover", admin.headers(), Map.of(
        "recoveryId", reported.get("recoveryId").toString(),
        "newHolderJwk", mapper.convertValue(fresh.jwk(), Map.class))))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void recoverNeedsFreshProof() throws Exception {
    TestAccount ops = TestAccounts.create(owner, "cun-proof", Set.of("ISSUER_OPS"));
    TestAccount admin = TestAccounts.createInTenant(
        owner, ops.tenantId(), "cun-proof-admin", Set.of("TRUST_ADMIN"));
    Case Case = approvedCase(ops);
    Map<String, Object> reported = post("/api/holder-keys/report", ops.headers(), Map.of(
        "thumbprint", IssuanceFixtures.thumbprint(Case.holder()), "reason", "theft"));
    String recoveryId = reported.get("recoveryId").toString();
    IssuanceFixtures.HolderKeys fresh = IssuanceFixtures.generateHolder(mapper);
    Map<String, Object> jwk = mapper.convertValue(fresh.jwk(), Map.class);
    // Proof from the lost key instead of the fresh key.
    String stale = IssuanceFixtures.proofOver(
        Case.holder(),
        "holder-recovery\n" + recoveryId + "\n" + IssuanceFixtures.thumbprint(fresh),
        mapper);
    assertThatThrownBy(() -> post("/api/holder-keys/recover", admin.headers(), Map.of(
        "recoveryId", recoveryId, "newHolderJwk", jwk, "newKeyProof", stale)))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
    // Proof for another recovery id.
    String misbound = IssuanceFixtures.proofOver(
        fresh,
        "holder-recovery\n" + UUID.randomUUID() + "\n" + IssuanceFixtures.thumbprint(fresh),
        mapper);
    assertThatThrownBy(() -> post("/api/holder-keys/recover", admin.headers(), Map.of(
        "recoveryId", recoveryId, "newHolderJwk", jwk, "newKeyProof", misbound)))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void operatorCannotRecover() throws Exception {
    TestAccount ops = TestAccounts.create(owner, "cun-role", Set.of("ISSUER_OPS"));
    Case Case = approvedCase(ops);
    Map<String, Object> reported = post("/api/holder-keys/report", ops.headers(), Map.of(
        "thumbprint", IssuanceFixtures.thumbprint(Case.holder()), "reason", "loss"));
    IssuanceFixtures.HolderKeys fresh = IssuanceFixtures.generateHolder(mapper);
    // Recovery is TRUST_ADMIN only, even with a valid fresh-key
    // proof (OD-09 administrator limits).
    assertThatThrownBy(() -> post("/api/holder-keys/recover", ops.headers(), Map.of(
        "recoveryId", reported.get("recoveryId").toString(),
        "newHolderJwk", mapper.convertValue(fresh.jwk(), Map.class),
        "newKeyProof", IssuanceFixtures.proofOver(
            fresh,
            "holder-recovery\n" + reported.get("recoveryId") + "\n"
                + IssuanceFixtures.thumbprint(fresh),
            mapper))))
        .isInstanceOf(HttpClientErrorException.Forbidden.class);
  }

  @Test
  void staleEnrollmentBlocksRecovery() throws Exception {
    TestAccount ops = TestAccounts.create(owner, "cun-stale", Set.of("ISSUER_OPS"));
    TestAccount admin = TestAccounts.createInTenant(
        owner, ops.tenantId(), "cun-stale-admin", Set.of("TRUST_ADMIN"));
    Case Case = approvedCase(ops);
    Map<String, Object> reported = post("/api/holder-keys/report", ops.headers(), Map.of(
        "thumbprint", IssuanceFixtures.thumbprint(Case.holder()), "reason", "loss"));
    // The source moves on after the report: recovery must
    // re-proof the live case, so it terminates (SEC-39).
    post("/api/extraction/records/" + Case.recordId() + "/revisions", ops.headers(), Map.of(
        "fields", Map.of("name", "Ana Fixed"), "confidence", 0.9));
    post("/api/extraction/records/" + Case.recordId() + "/approval", ops.headers(),
        Map.of("revision", 2));
    IssuanceFixtures.HolderKeys fresh = IssuanceFixtures.generateHolder(mapper);
    assertThatThrownBy(() -> post("/api/holder-keys/recover", admin.headers(), Map.of(
        "recoveryId", reported.get("recoveryId").toString(),
        "newHolderJwk", mapper.convertValue(fresh.jwk(), Map.class),
        "newKeyProof", IssuanceFixtures.proofOver(
            fresh,
            "holder-recovery\n" + reported.get("recoveryId") + "\n"
                + IssuanceFixtures.thumbprint(fresh),
            mapper))))
        .isInstanceOf(HttpClientErrorException.Conflict.class);
  }

  @Test
  void doubleReportAndRecoverConflict() throws Exception {
    TestAccount ops = TestAccounts.create(owner, "cun-dbl", Set.of("ISSUER_OPS"));
    TestAccount admin = TestAccounts.createInTenant(
        owner, ops.tenantId(), "cun-dbl-admin", Set.of("TRUST_ADMIN"));
    Case Case = approvedCase(ops);
    String thumbprint = IssuanceFixtures.thumbprint(Case.holder());
    Map<String, Object> reported = post("/api/holder-keys/report", ops.headers(),
        Map.of("thumbprint", thumbprint, "reason", "loss"));
    assertThatThrownBy(() -> post("/api/holder-keys/report", ops.headers(),
        Map.of("thumbprint", thumbprint, "reason", "theft")))
        .isInstanceOf(HttpClientErrorException.Conflict.class);
    IssuanceFixtures.HolderKeys fresh = IssuanceFixtures.generateHolder(mapper);
    Map<String, Object> body = Map.of(
        "recoveryId", reported.get("recoveryId").toString(),
        "newHolderJwk", mapper.convertValue(fresh.jwk(), Map.class),
        "newKeyProof", IssuanceFixtures.proofOver(
            fresh,
            "holder-recovery\n" + reported.get("recoveryId") + "\n"
                + IssuanceFixtures.thumbprint(fresh),
            mapper));
    post("/api/holder-keys/recover", admin.headers(), body);
    assertThatThrownBy(() -> post("/api/holder-keys/recover", admin.headers(), body))
        .isInstanceOf(HttpClientErrorException.Conflict.class);
  }

  @Test
  void unknownThumbprintReportIsNotFound() {
    TestAccount ops = TestAccounts.create(owner, "cun-unknown", Set.of("ISSUER_OPS"));
    assertThatThrownBy(() -> post("/api/holder-keys/report", ops.headers(),
        Map.of("thumbprint", "no-such-key", "reason", "loss")))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
  }

  @Test
  void crossTenantReadIsNotFound() throws Exception {
    TestAccount ops = TestAccounts.create(owner, "cun-tenant", Set.of("ISSUER_OPS"));
    Case Case = approvedCase(ops);
    Map<String, Object> reported = post("/api/holder-keys/report", ops.headers(), Map.of(
        "thumbprint", IssuanceFixtures.thumbprint(Case.holder()), "reason", "loss"));
    TestAccount stranger = TestAccounts.create(owner, "cun-stranger", Set.of("ISSUER_OPS"));
    assertThatThrownBy(() -> client.get().uri("/api/holder-keys/" + reported.get("keyId"))
        .headers(stranger.headers()).retrieve().body(Map.class))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
  }

  @Test
  void noPrivateMaterialStored() throws Exception {
    TestAccount ops = TestAccounts.create(owner, "cun-priv", Set.of("ISSUER_OPS"));
    approvedCase(ops);
    // The registry holds public keys only: no stored JWK carries a
    // private field (OD-09, DR-10 scenario 8).
    List<String> jwks = owner.queryForList(
        "SELECT jwk::text FROM holder_key WHERE tenant_id = ?",
        String.class, ops.tenantId());
    assertThat(jwks).isNotEmpty();
    for (String jwk : jwks) {
      assertThat(mapper.readTree(jwk).has("d")).isFalse();
    }
  }

  private record Case(String enrollmentId, String recordId, IssuanceFixtures.HolderKeys holder) {}

  private Case approvedCase(TestAccount ops) throws Exception {
    TestAccount checker = TestAccounts.createInTenant(
        owner, ops.tenantId(), "cun-checker-" + UUID.randomUUID().toString().substring(0, 8),
        Set.of("ISSUER_OPS"));
    byte[] content = HolderCustodyFlowTests.FIXTURE.getBytes(StandardCharsets.UTF_8);
    Map<String, Object> stored = post("/api/vault/objects", ops.headers(), Map.of(
        "issuerId", "https://issuer.example/custody-neg",
        "displayName", "custody source",
        "purposes", List.of("extraction-run"),
        "contentBase64", Base64.getEncoder().encodeToString(content),
        "contentSha256Hex", sha256Hex(HolderCustodyFlowTests.FIXTURE)));
    String objectId = stored.get("objectId").toString();
    Map<String, Object> granted = post("/api/vault/grants", ops.headers(), Map.of(
        "objectId", objectId, "objectVersion", 1, "principalType", "service_account",
        "principalId", ops.accountId().toString(), "purpose", "extraction-run",
        "workload", "sovra-test", "ttlSeconds", 3600));
    Map<String, Object> run = post("/api/extraction/records", ops.headers(), Map.of(
        "vaultObjectId", objectId, "objectVersion", 1,
        "grantId", granted.get("grantId").toString(), "purpose", "extraction-run",
        "workload", "sovra-test", "schemaId", "fixture-doc-v1"));
    String recordId = run.get("recordId").toString();
    post("/api/extraction/records/" + recordId + "/approval", ops.headers(),
        Map.of("revision", 1));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    Map<String, Object> created = post("/api/enrollments", ops.headers(), Map.of(
        "vaultObjectId", objectId, "extractionRecordId", recordId,
        "holderJwk", mapper.convertValue(holder.jwk(), Map.class)));
    String enrollmentId = created.get("enrollmentId").toString();
    post("/api/enrollments/" + enrollmentId + "/submit", ops.headers(), Map.of());
    post("/api/enrollments/" + enrollmentId + "/decision", checker.headers(), Map.of(
        "revision", 1, "decision", "approve",
        "bindingProof", IssuanceFixtures.proofOver(
            holder, "enrollment-binding\n" + enrollmentId + "\n1", mapper)));
    return new Case(enrollmentId, recordId, holder);
  }

  private static String sha256Hex(String text) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
          .digest(text.getBytes(StandardCharsets.UTF_8)));
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private Map<String, Object> post(
      String uri, Consumer<HttpHeaders> headers, Map<String, Object> body) {
    return client.post().uri(uri).headers(headers).body(body).retrieve().body(Map.class);
  }
}
