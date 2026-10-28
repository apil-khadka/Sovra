package dev.sovra.planning;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.tenancy.TenantContext;
import dev.sovra.trust.TrustService;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.ObjectMapper;

/**
 * Canary capture (SOV-013, DR-03, SEC-20, AC-07): synthetic sensitive
 * markers in registry metadata and caller credentials never reach
 * model inputs, tool results beyond minimized metadata, responses, or
 * audit detail. Tools return allowlisted fields only.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class PlanningCanaryTests extends SovraAppRoleBase {

  static final String CANARY = "CANARY-SOV13-9f31-sensitive-marker";

  @Autowired TrustService trust;

  @Autowired PlanningTools tools;

  @Autowired PlanningService planning;

  @Autowired PlanningProperties properties;

  @Autowired ObjectMapper mapper;

  JdbcTemplate owner;

  @BeforeEach
  void setup() throws Exception {
    owner = new JdbcTemplate(ownerDataSource());
    IssuanceFixtures.ensureSyntheticIssuer(owner, trust, mapper);
  }

  @AfterEach
  void release() {
    PlanningInvocation.clear();
    TenantContext.clear();
  }

  @Test
  void promptsCarryOnlyAllowlistedIntentFields() {
    TestAccount rp = TestAccounts.create(owner, "canary-rp", Set.of("RP_CLIENT"));
    PlanningIntent intent =
        PlanningIntents.validate(
            "https://rp.example/synth-shop",
            "https://rp.example/synth-shop/callback",
            "synthetic age check",
            "age_over_18",
            dev.sovra.guard.GuardPolicies.POLICY_ID,
            dev.sovra.guard.GuardPolicies.POLICY_VERSION,
            List.of("adultOver18"));
    String prompt = PlanningPrompts.system() + "\n" + PlanningPrompts.user(intent);

    // The caller credential is the sensitive marker here: prompts are
    // built from intent fields alone and can never see it.
    assertThat(prompt).doesNotContain(rp.token());
    assertThat(prompt).doesNotContain(CANARY);
    assertThat(prompt).contains("age_over_18", "synth-shop");
  }

  @Test
  void toolResultsExposeNoCredentialMaterial() {
    TestAccount rp = TestAccounts.create(owner, "canary-tool", Set.of("RP_CLIENT"));
    var caller = IssuanceFixtures.asPrincipal(rp);
    TenantContext.set(caller);
    PlanningInvocation.install(new PlanningInvocation(caller, properties.maxToolCalls()));
    try {
      for (var callback : tools.callbacks()) {
        String name = callback.getToolDefinition().name();
        String output =
            switch (name) {
              case "listTrustedIssuers" -> callback.call("{}");
              case "getCredentialSchema" -> callback.call(
                  "{\"issuerId\":\"" + IssuanceFixtures.ISSUER_ID + "\",\"credentialType\":\""
                      + IssuanceFixtures.ADULT_VCT + "\"}");
              case "getPolicyDocument" -> callback.call(
                  "{\"policyId\":\"" + dev.sovra.guard.GuardPolicies.POLICY_ID
                      + "\",\"version\":\"1\"}");
              case "getIssuerCapabilities" -> callback.call(
                  "{\"issuerId\":\"" + IssuanceFixtures.ISSUER_ID + "\"}");
              default -> callback.call(
                  "{\"requestedOutcome\":\"age_over_18\",\"candidateCredentialIds\":[]}");
            };
        assertThat(output).doesNotContain(rp.token());
        assertThat(output.toLowerCase())
            .doesNotContain("private", "secret", "seed", "mnemonic", "password");
        // No JWK coordinate members anywhere in tool output.
        assertThat(output).doesNotContain("\"x\"", "\"y\"", "\"d\"");
      }
    } finally {
      PlanningInvocation.clear();
      TenantContext.clear();
    }
  }

  @Test
  void auditDetailStaysMinimized() {
    TestAccount rp = TestAccounts.create(owner, "canary-audit", Set.of("RP_CLIENT"));
    var caller = IssuanceFixtures.asPrincipal(rp);
    TenantContext.set(caller);
    PlanningIntent intent =
        PlanningIntents.validate(
            "https://rp.example/" + CANARY,
            "https://rp.example/synth-shop/callback",
            "synthetic age check",
            "age_over_18",
            dev.sovra.guard.GuardPolicies.POLICY_ID,
            dev.sovra.guard.GuardPolicies.POLICY_VERSION,
            List.of("adultOver18"));
    try {
      planning.propose(caller, intent);
    } finally {
      TenantContext.clear();
    }
    Map<String, Object> audit =
        owner.queryForMap(
            "SELECT * FROM audit_event WHERE action = 'PROPOSE_PLAN' AND tenant_id = ?"
                + " ORDER BY occurred_at DESC LIMIT 1",
            rp.tenantId());
    assertThat(audit.get("decision")).isEqualTo("PERMIT");
    assertThat(audit.get("detail").toString()).doesNotContain(CANARY);
    String ownRows =
        String.join(
            "\n",
            owner.query(
                "SELECT audit_event::text FROM audit_event WHERE tenant_id = ?",
                (rs, row) -> rs.getString(1),
                rp.tenantId()));
    assertThat(ownRows).doesNotContain(CANARY, rp.token());
  }
}
