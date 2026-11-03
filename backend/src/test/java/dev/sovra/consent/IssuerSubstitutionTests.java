package dev.sovra.consent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.guard.CandidatePlan;
import dev.sovra.guard.GuardPolicies;
import dev.sovra.issuance.DualIssuerFixtures;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.issuance.LocalDevSigner;
import dev.sovra.tenancy.TenantContext;
import dev.sovra.trust.TrustService;
import dev.sovra.trust.TrustSnapshotProvider;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Consent binds BOTH stored credential issuer and type to the approved
 * plan. With two trusted issuers attesting the SAME type, a guarded plan
 * naming issuer B attached to an issuer A credential must refuse — the
 * check must not rely on today's disjoint synth-1/synth-2 type lists.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class IssuerSubstitutionTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  @Autowired TrustService trust;

  @Autowired TrustSnapshotProvider snapshots;

  @Autowired ObjectMapper mapper;

  RestClient client;
  JdbcTemplate owner;

  @BeforeEach
  void setup() throws Exception {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
    DualIssuerFixtures.ensureDualIssuers(owner, trust, mapper);
    // Register the synth-2 public key, then activate a snapshot where BOTH
    // issuers attest the legacy adult-status type (same-type fixture).
    new LocalDevSigner(
        ownerDataSource(), snapshots, mapper, Clock.systemUTC(), true, true, "synth-2");
    String secondJwk = owner.queryForObject(
        "SELECT public_key_jwk::text FROM issuer_signing_key"
            + " WHERE issuer_id = ? AND key_id = 'synth-2' AND key_version = 1",
        String.class, LocalDevSigner.SECOND_ISSUER_ID);
    var current = trust.currentSnapshot().orElseThrow();
    TestAccount maker = TestAccounts.create(owner, "subst-maker", Set.of("TRUST_ADMIN"));
    TestAccount checker = TestAccounts.create(owner, "subst-checker", Set.of("TRUST_ADMIN"));
    Instant now = Instant.now();
    var issuers = new java.util.ArrayList<TrustService.IssuerInput>();
    for (var view : current.issuers()) {
      if (IssuanceFixtures.ISSUER_ID.equals(view.issuerId())) {
        issuers.add(new TrustService.IssuerInput(
            view.issuerId(), view.displayName(), view.scope(),
            List.of(IssuanceFixtures.ADULT_VCT), view.keyId(), view.keyVersion(),
            view.publicKeyJwk(), now.minusSeconds(60), now.plusSeconds(3600), "ACTIVE"));
      }
    }
    issuers.add(new TrustService.IssuerInput(
        LocalDevSigner.SECOND_ISSUER_ID,
        "Synthetic second issuer (non-production)",
        "synthetic-only",
        List.of(IssuanceFixtures.ADULT_VCT),
        "synth-2", 1, mapper.readTree(secondJwk),
        now.minusSeconds(60), now.plusSeconds(3600), "ACTIVE"));
    TenantContext.set(new dev.sovra.auth.ServiceAccountPrincipal(
        maker.accountId(), maker.tenantId(), maker.name(), maker.roles()));
    TrustService.ProposalResult result;
    try {
      result = trust.propose(
          TenantContext.current().orElseThrow(),
          new TrustService.ProposalInput(issuers, List.of()),
          "test: both issuers attest adult-status");
    } finally {
      TenantContext.clear();
    }
    TenantContext.set(new dev.sovra.auth.ServiceAccountPrincipal(
        checker.accountId(), checker.tenantId(), checker.name(), checker.roles()));
    try {
      trust.approve(TenantContext.current().orElseThrow(), result.proposalId());
      trust.activate(TenantContext.current().orElseThrow(), result.version());
    } finally {
      TenantContext.clear();
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void crossIssuerPlanOnSameTypeCredentialRefuses() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "subst-issuer", Set.of("ISSUER_OPS"));
    TestAccount rp = TestAccounts.createInTenant(
        owner, issuer.tenantId(), "subst-rp", Set.of("RP_CLIENT"));
    var holder = IssuanceFixtures.generateHolder(mapper);
    String credentialId = ConsentFixtures.issueCredential(client, issuer, holder, mapper);

    // Guard-accepted plan naming synth-2 for the SAME type.
    CandidatePlan foreign = ConsentFixtures.mappedPlan(
        LocalDevSigner.SECOND_ISSUER_ID,
        IssuanceFixtures.ADULT_VCT,
        "adultOver18");
    Map<String, Object> guard = client.post().uri("/api/guard/validate")
        .headers(rp.headers())
        .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
        .body(Map.of(
            "plan", ConsentFixtures.planBody(foreign),
            "policyId", foreign.policyId(),
            "policyVersion", foreign.policyVersion()))
        .retrieve().body(Map.class);
    assertThat(guard.get("accepted")).isEqualTo(Boolean.TRUE);

    Map<String, Object> body = ConsentFixtures.createBodyFor(
        UUID.fromString(credentialId), foreign, Map.of("adultOver18", Boolean.TRUE));
    assertThatThrownBy(() -> ConsentFixtures.create(client, rp, body))
        .isInstanceOf(HttpClientErrorException.BadRequest.class);
  }

  @Test
  void sameIssuerPlanOnSameTypeCredentialSucceeds() throws Exception {
    TestAccount issuer = TestAccounts.create(owner, "subst-ok-issuer", Set.of("ISSUER_OPS"));
    TestAccount rp = TestAccounts.createInTenant(
        owner, issuer.tenantId(), "subst-ok-rp", Set.of("RP_CLIENT"));
    var holder = IssuanceFixtures.generateHolder(mapper);
    String credentialId = ConsentFixtures.issueCredential(client, issuer, holder, mapper);

    CandidatePlan own = ConsentFixtures.validPlan();
    Map<String, Object> body = ConsentFixtures.createBodyFor(
        UUID.fromString(credentialId), own, Map.of("adultOver18", Boolean.TRUE));
    Map<String, Object> created = ConsentFixtures.create(client, rp, body);
    assertThat(created.get("requestId")).isNotNull();
    assertThat(created.get("state")).isEqualTo("PENDING");
  }
}
