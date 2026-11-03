package dev.sovra.planning;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.guard.ApprovedSchemas;
import dev.sovra.issuance.DualIssuerFixtures;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.issuance.LocalDevSigner;
import dev.sovra.tenancy.TenantContext;
import dev.sovra.trust.TrustService;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.ObjectMapper;

/**
 * Tool-level invocation scope: scoped calls see only narrowed approved
 * metadata (unscoped calls are unchanged). Out-of-scope reads answer the
 * same fail-closed shapes as unknown references — scope never widens.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ToolScopeTests extends SovraAppRoleBase {

  @Autowired TrustService trust;

  @Autowired PlanningTools tools;

  @Autowired PlanningProperties properties;

  @Autowired ObjectMapper mapper;

  JdbcTemplate owner;

  @BeforeEach
  void setup() throws Exception {
    owner = new JdbcTemplate(ownerDataSource());
    DualIssuerFixtures.ensureDualIssuers(owner, trust, mapper);
  }

  @AfterEach
  void release() {
    PlanningInvocation.clear();
    TenantContext.clear();
  }

  private <T> T asCaller(
      TestAccount account, List<String> issuers, List<String> types, Supplier<T> work) {
    var caller = IssuanceFixtures.asPrincipal(account);
    TenantContext.set(caller);
    PlanningInvocation.install(new PlanningInvocation(
        caller, properties.maxToolCalls(), issuers, types, List.of()));
    try {
      return work.get();
    } finally {
      PlanningInvocation.clear();
      TenantContext.clear();
    }
  }

  private String call(String tool, String args) {
    return tools.dispatch(tool).call(args);
  }

  @Test
  void scopedListingNarrowsToOneIssuer() {
    TestAccount rp = TestAccounts.create(owner, "tscope-list", Set.of("RP_CLIENT"));
    String scoped = asCaller(
        rp, List.of(LocalDevSigner.SECOND_ISSUER_ID), List.of(),
        () -> call("listTrustedIssuers", "{}"));
    assertThat(scoped).contains(LocalDevSigner.SECOND_ISSUER_ID);
    assertThat(scoped).doesNotContain(IssuanceFixtures.ISSUER_ID);

    String open = asCaller(
        rp, List.of(), List.of(), () -> call("listTrustedIssuers", "{}"));
    assertThat(open).contains(IssuanceFixtures.ISSUER_ID);
    assertThat(open).contains(LocalDevSigner.SECOND_ISSUER_ID);
  }

  @Test
  void outOfScopeSchemaReadsFailClosed() {
    TestAccount rp = TestAccounts.create(owner, "tscope-schema", Set.of("RP_CLIENT"));
    String hidden = asCaller(
        rp, List.of(LocalDevSigner.SECOND_ISSUER_ID), List.of(),
        () -> call("getCredentialSchema",
            "{\"issuerId\":\"" + IssuanceFixtures.ISSUER_ID + "\","
                + "\"credentialType\":\"" + IssuanceFixtures.ADULT_VCT + "\"}"));
    assertThat(hidden).contains("unknown_issuer");

    String shown = asCaller(
        rp, List.of(LocalDevSigner.SECOND_ISSUER_ID), List.of(),
        () -> call("getCredentialSchema",
            "{\"issuerId\":\"" + LocalDevSigner.SECOND_ISSUER_ID + "\","
                + "\"credentialType\":\"" + ApprovedSchemas.FJORD_VCT + "\"}"));
    assertThat(shown).contains("isAdult");
    assertThat(shown).contains("sovra-synthetic-schemas/1");
    assertThat(shown).contains("age_over_18");
  }

  @Test
  void employmentSchemaExposesIncompatibleMetadata() {
    TestAccount rp = TestAccounts.create(owner, "tscope-tenure", Set.of("RP_CLIENT"));
    String result = asCaller(
        rp, List.of(), List.of(),
        () -> call("getCredentialSchema",
            "{\"issuerId\":\"" + LocalDevSigner.SECOND_ISSUER_ID + "\","
                + "\"credentialType\":\"" + ApprovedSchemas.EMPLOYMENT_VCT + "\"}"));
    assertThat(result).contains("\"compatible\":false");
    assertThat(result).contains("employment_tenure_years");
    assertThat(result).contains("yearsInEmployment");
  }

  @Test
  void outOfScopeCompareHintsUnknown() {
    TestAccount rp = TestAccounts.create(owner, "tscope-compare", Set.of("RP_CLIENT"));
    String result = asCaller(
        rp, List.of(LocalDevSigner.SECOND_ISSUER_ID), List.of(),
        () -> call("compareEvidence",
            "{\"requestedOutcome\":\"age_over_18\",\"candidateCredentialIds\":[\""
                + IssuanceFixtures.ISSUER_ID + "|" + IssuanceFixtures.ADULT_VCT + "\",\""
                + LocalDevSigner.SECOND_ISSUER_ID + "|" + ApprovedSchemas.FJORD_VCT + "\"]}"));
    assertThat(result).contains("outside the requested discovery scope");
    assertThat(result).contains("\"compatible\"");
  }
}
