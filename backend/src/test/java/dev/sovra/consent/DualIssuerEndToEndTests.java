package dev.sovra.consent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.guard.ApprovedSchemas;
import dev.sovra.guard.CandidatePlan;
import dev.sovra.issuance.DualIssuerFixtures;
import dev.sovra.issuance.DualIssuerTestDouble;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.issuance.IssuerSigner;
import dev.sovra.issuance.LocalDevSigner;
import dev.sovra.trust.TrustService;
import dev.sovra.trust.TrustSnapshotProvider;
import dev.sovra.verification.VerificationFixtures;
import java.time.Clock;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Unfamiliar-schema end-to-end over the synthetic profile: fjord issuance,
 * mapped-policy guard acceptance, consent with the ACTUAL returned plan
 * (per-schema canonical bytes), and verification ACCEPTED. Single-JVM
 * signing goes through the labelled {@link DualIssuerTestDouble}; tenant
 * rows stay RLS-isolated across issuer operators (logical separation
 * only, not sovereignty).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class DualIssuerEndToEndTests extends SovraAppRoleBase {

  @TestConfiguration
  static class DualSigning {
    @Bean
    @Primary
    IssuerSigner dualSigner(
        DataSource dataSource,
        TrustSnapshotProvider snapshots,
        ObjectMapper mapper,
        Clock clock) throws Exception {
      return new DualIssuerTestDouble(dataSource, snapshots, mapper, clock);
    }
  }

  @LocalServerPort int port;

  @Autowired TrustService trust;

  @Autowired ObjectMapper mapper;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() throws Exception {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
    DualIssuerFixtures.ensureDualIssuers(owner, trust, mapper);
  }

  @Test
  @SuppressWarnings("unchecked")
  void fjordIssuanceConsentAndVerificationAccept() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "fjord-issuer", Set.of("ISSUER_OPS"));
    TestAccount rp = TestAccounts.createInTenant(
        owner, issuer.tenantId(), "fjord-rp", Set.of("RP_CLIENT"));
    TestAccount agent = TestAccounts.createInTenant(
        owner, issuer.tenantId(), "fjord-agent", Set.of("TENANT_MEMBER"));
    var holder = IssuanceFixtures.generateHolder(mapper);

    String credentialId = ConsentFixtures.issueCredentialFor(
        client, issuer, holder,
        LocalDevSigner.SECOND_ISSUER_ID, ApprovedSchemas.FJORD_VCT,
        Map.of("isAdult", Boolean.TRUE), "isAdult=true", mapper);

    // Mapped-policy guard acceptance for the fjord wire pair.
    CandidatePlan plan = ConsentFixtures.mappedPlan(
        LocalDevSigner.SECOND_ISSUER_ID, ApprovedSchemas.FJORD_VCT, "isAdult");
    Map<String, Object> guard = client.post().uri("/api/guard/validate")
        .headers(rp.headers())
        .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
        .body(Map.of(
            "plan", ConsentFixtures.planBody(plan),
            "policyId", plan.policyId(),
            "policyVersion", plan.policyVersion()))
        .retrieve().body(Map.class);
    assertThat(guard.get("accepted")).isEqualTo(Boolean.TRUE);
    assertThat(guard.get("code")).isEqualTo("GUARD_ACCEPTED");

    // Consent with the ACTUAL plan (per-schema canonical consent bytes).
    Map<String, Object> created = ConsentFixtures.create(
        client, rp, ConsentFixtures.createBodyFor(
            UUID.fromString(credentialId), plan, Map.of("isAdult", Boolean.TRUE)));
    String requestId = created.get("requestId").toString();
    Map<String, Object> review = ConsentFixtures.review(client, rp, requestId);
    Map<String, Object> decideBody = new java.util.LinkedHashMap<>();
    decideBody.put("decision", "approve");
    decideBody.put("holderJwk", mapper.convertValue(holder.jwk(), Map.class));
    decideBody.put("consentProof",
        ConsentFixtures.consentProofFor(holder, review, "approve", "isAdult=true", mapper));
    Map<String, Object> decided = ConsentFixtures.decide(client, agent, requestId, decideBody);
    assertThat(decided.get("state")).isEqualTo("VERIFIED");

    String nonce = VerificationFixtures.nonce();
    Map<String, Object> verdict = VerificationFixtures.verify(
        client, rp, VerificationFixtures.verifyBody(
            holder, requestId, nonce, ConsentFixtures.AUDIENCE, mapper));
    assertThat(verdict.get("outcome")).isEqualTo("ACCEPTED");
    assertThat(verdict.get("reasonCode")).isEqualTo("OK");
  }

  @Test
  void issuerOperatorRowsStayTenantIsolated() throws Exception {
    TestAccount issuerA = TestAccounts.create(owner, "iso-a", Set.of("ISSUER_OPS"));
    TestAccount issuerB = TestAccounts.create(owner, "iso-b", Set.of("ISSUER_OPS"));
    var holderA = IssuanceFixtures.generateHolder(mapper);
    var holderB = IssuanceFixtures.generateHolder(mapper);
    String credA = ConsentFixtures.issueCredential(client, issuerA, holderA, mapper);
    String credB = ConsentFixtures.issueCredentialFor(
        client, issuerB, holderB,
        LocalDevSigner.SECOND_ISSUER_ID, ApprovedSchemas.FJORD_VCT,
        Map.of("isAdult", Boolean.TRUE), "isAdult=true", mapper);

    // Both rows exist under distinct tenants (owner bypasses RLS to see).
    Integer tenants = owner.queryForObject(
        "SELECT COUNT(DISTINCT tenant_id) FROM credential_artifact WHERE id IN (?, ?)",
        Integer.class, UUID.fromString(credA), UUID.fromString(credB));
    assertThat(tenants).isEqualTo(2);

    // Cross-tenant reads fail closed (logical separation, not sovereignty).
    assertThatThrownBy(() -> client.get()
            .uri("/api/issuance/credentials/" + credB)
            .headers(issuerA.headers())
            .retrieve().body(String.class))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
    assertThatThrownBy(() -> client.get()
            .uri("/api/issuance/credentials/" + credA)
            .headers(issuerB.headers())
            .retrieve().body(String.class))
        .isInstanceOf(HttpClientErrorException.NotFound.class);
  }

  @Test
  void employmentIssuanceIsRefused() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "tenure-issuer", Set.of("ISSUER_OPS"));
    var holder = IssuanceFixtures.generateHolder(mapper);
    String key = "tenure-" + UUID.randomUUID();
    Map<String, Object> body = new java.util.LinkedHashMap<>();
    body.put("issuerId", LocalDevSigner.SECOND_ISSUER_ID);
    body.put("vct", ApprovedSchemas.EMPLOYMENT_VCT);
    body.put("holderJwk", mapper.convertValue(holder.jwk(), Map.class));
    body.put("holderProof", IssuanceFixtures.proofWithClaims(
        holder, key, ApprovedSchemas.EMPLOYMENT_VCT, "yearsInEmployment=18", mapper));
    body.put("claims", Map.of("yearsInEmployment", 18));
    body.put("expiresAt", java.time.Instant.now().plusSeconds(7200).toString());
    assertThatThrownBy(() -> client.post().uri("/api/issuance/credentials")
            .headers(h -> {
              issuer.headers().accept(h);
              h.set("Idempotency-Key", key);
            })
            .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
            .body(body)
            .retrieve().body(String.class))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }
}
