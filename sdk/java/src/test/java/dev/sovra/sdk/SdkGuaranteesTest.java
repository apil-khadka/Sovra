package dev.sovra.sdk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

/**
 * Cross-cutting SDK guarantees (SOV-021, SEC-29/42/43): origin
 * validation, typed sanitized errors, idempotent replay, and ETag
 * misses. No network needed except where noted.
 */
class SdkGuaranteesTest extends SdkLiveBase {

  @Test
  void originsValidateAtConstruction() {
    assertThatThrownBy(() -> new SovraClient("http://example.com", "t"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("https");
    assertThatThrownBy(() -> new SovraClient("not-a-url)://", "t"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new SovraClient("http://localhost:8080", " "))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("token");
    try (SovraClient loopback = new SovraClient("http://localhost:8080/", "t");
        SovraClient loopbackIp = new SovraClient("http://127.0.0.1:8080", "t");
        SovraClient tls = new SovraClient("https://sovra.example", "t")) {
      assertThat(SovraClient.SUPPORTED_CONTRACT).isEqualTo("0.13.0");
    }
  }

  @Test
  void idempotencyKeysMatchTheServerAlphabet() {
    assertThat(Idempotency.valid(Idempotency.mint())).isTrue();
    assertThat(Idempotency.valid("has space")).isFalse();
    assertThat(Idempotency.valid(null)).isFalse();
  }

  @Test
  void unauthorizedMapsToTypedSanitizedErrors() throws Exception {
    MachineAccount account = mintAccount("sdk-guarantee", "TENANT_MEMBER");
    try (SovraClient bad = clientFor("sovra_test_definitely-not-a-token");
        SovraClient member = clientFor(account.token())) {
      // 401 carries no token echo.
      assertThatThrownBy(() -> bad.ops.whoami())
          .isInstanceOf(SovraApiError.class)
          .satisfies(e -> {
            SovraApiError error = (SovraApiError) e;
            assertThat(error.status()).isEqualTo(401);
            assertThat(error.getMessage()).doesNotContain("definitely-not-a-token");
            assertThat(error.toString()).doesNotContain("definitely-not-a-token");
          });
      // 403 for a role the member lacks.
      assertThatThrownBy(member.trust::proposals)
          .isInstanceOf(SovraApiError.class)
          .satisfies(e -> assertThat(((SovraApiError) e).status()).isEqualTo(403));
    }
  }

  @Test
  void idempotentIssuanceReplaysByteIdentically() throws Exception {
    MachineAccount account = mintAccount("sdk-idempotent", "ISSUER_OPS");
    ObjectMapper mapper = new ObjectMapper();
    TestHolders.HolderKeys holder = TestHolders.generate(mapper);
    String key = Idempotency.mint();
    String proof = issuanceProof(holder, key);
    Map<String, Object> jwk = mapper.convertValue(holder.jwk(), Map.class);
    String expires = Instant.now().plusSeconds(3600).toString();
    try (SovraClient client = clientFor(account.token())) {
      IssuanceClient.IssuedCredential first = client.issuance.issue(
          key, ISSUER_ID, ADULT_VCT, holder.jwk(), proof,
          Map.of("adultOver18", Boolean.TRUE), expires, null);
      IssuanceClient.IssuedCredential replay = client.issuance.issue(
          key, ISSUER_ID, ADULT_VCT, holder.jwk(), proof,
          Map.of("adultOver18", Boolean.TRUE), expires, null);
      assertThat(replay.credentialId()).isEqualTo(first.credentialId());
      assertThat(replay.artifact()).isEqualTo(first.artifact());
      // Same key, different content: conflict, no second credential.
      String later = Instant.now().plusSeconds(7200).toString();
      assertThatThrownBy(() -> client.issuance.issue(
          key, ISSUER_ID, ADULT_VCT, holder.jwk(), proof,
          Map.of("adultOver18", Boolean.TRUE), later, null))
          .isInstanceOf(SovraApiError.class)
          .satisfies(e -> assertThat(((SovraApiError) e).status()).isEqualTo(409));
    }
  }

  @Test
  void conditionalReadsReport304AsEmpty() throws Exception {
    MachineAccount account = mintAccount("sdk-etag", "ISSUER_OPS");
    try (SovraClient client = clientFor(account.token())) {
      String fixture = "SOVRA-FIXTURE/v1\nname: Ana Example\ndocument_number: X1\n"
          + "date_of_birth: 1990-01-02\n";
      VaultClient.StoredVersion stored = client.vault.store(
          "https://issuer.example/sdk-etag", "etag source", List.of("extraction-run"),
          fixture.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      VaultClient.GrantView grant = client.vault.grant(
          stored.objectId(), 1, "service_account", null, "extraction-run", "sdk-test", 3600);
      ExtractionClient.RunResult run = client.extraction.run(
          stored.objectId(), 1, grant.grantId(), "extraction-run", "sdk-test", "fixture-doc-v1");
      SovraClient.Tagged<ExtractionClient.RecordView> tagged = client.getTagged(
          "/api/extraction/records/" + run.recordId(), null, ExtractionClient.RecordView.class)
          .orElseThrow();
      assertThat(tagged.value().engineId()).isEqualTo("fixture-v1");
      assertThat(tagged.etag()).isNotBlank();
      assertThat(client.extraction.get(run.recordId(), tagged.etag())).isEmpty();
    }
  }

  static String issuanceProof(TestHolders.HolderKeys holder, String key) throws Exception {
    return TestHolders.proofOver(holder,
        "sovra-issuance-proof/v1\n" + key + "\n" + ADULT_VCT + "\n"
            + TestHolders.thumbprint(holder) + "\nadultOver18=true");
  }
}
