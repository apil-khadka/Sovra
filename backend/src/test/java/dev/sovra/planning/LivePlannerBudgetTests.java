package dev.sovra.planning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraPostgresBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.guard.GuardPolicies;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.ObjectMapper;

/**
 * Live-AI session budget envelope (PROD-012): real tools, prompts, and
 * ledger against the fake provider — per-round funding, exact abort
 * settle, uncertain burn on failure, pre-spend gates, and the guard's
 * byte estimates meeting every real request body. No real provider.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class LivePlannerBudgetTests extends SovraPostgresBase {

  @Autowired PlanningTools tools;

  @Autowired TrustService trust;

  @Autowired ObjectMapper mapper;

  @Autowired PlanningProperties defaultProperties;

  JdbcTemplate owner;
  JdbcTemplate app;

  @BeforeEach
  void setup() throws Exception {
    owner = new JdbcTemplate(ownerDataSource());
    app = new JdbcTemplate(appRoleDataSource());
    owner.update("DELETE FROM ai_call_lease");
    owner.update("DELETE FROM ai_budget_day");
    IssuanceFixtures.ensureSyntheticIssuer(owner, trust, mapper);
  }

  private PlanningIntent intent() {
    return new PlanningIntent(
        "https://rp.example/synth-shop",
        "https://rp.example/synth-shop/callback",
        "synthetic age check at checkout",
        "age_over_18",
        GuardPolicies.POLICY_ID,
        GuardPolicies.POLICY_VERSION,
        List.of("adultOver18"),
        List.of(),
        List.of(),
        List.of());
  }

  private String candidate() {
    return "{\"plan_id\":\"pln_probe_001\",\"requested_outcome\":\"age_over_18\","
        + "\"candidate_issuer_id\":\"" + IssuanceFixtures.ISSUER_ID + "\","
        + "\"credential_type\":\"https://sovra.example/vct/adult-status/1\","
        + "\"claim_paths\":[\"adultOver18\"],"
        + "\"evidence\":[{\"document_id\":\"" + GuardPolicies.POLICY_ID
        + "\",\"section_id\":\"age_eligibility\"}],"
        + "\"policy_id\":\"" + GuardPolicies.POLICY_ID + "\",\"policy_version\":\"1\","
        + "\"recommendation\":\"CANDIDATE_ONLY\"}";
  }

  private PlanningProperties properties(FakeOpenAiProvider fake) {
    PlanningProperties props = new PlanningProperties();
    props.setLiveEnabled(true);
    props.setBaseUrl(fake.baseUrl());
    props.setApiKey("test-only-key");
    props.setModel("fake-model");
    props.setAllowedModels(List.of("fake-model"));
    props.setTimeout(Duration.ofSeconds(10));
    props.setMaxRetries(0);
    return props;
  }

  private AiBudgetService ledger(long dailyTokens) {
    return ledger(dailyTokens, 120);
  }

  private AiBudgetService ledger(long dailyTokens, int leaseSeconds) {
    AiBudgetProperties budgets = new AiBudgetProperties();
    budgets.setDailyRequests(100);
    budgets.setDailyTokens(dailyTokens);
    budgets.setMaxConcurrency(10);
    budgets.setLeaseSeconds(leaseSeconds);
    return new AiBudgetService(appRoleDataSource(), Clock.systemUTC(), budgets);
  }

  private ServiceAccountPrincipal caller(String name) {
    TestAccount rp = TestAccounts.create(owner, name, Set.of("RP_CLIENT"));
    return new ServiceAccountPrincipal(rp.accountId(), rp.tenantId(), rp.name(), rp.roles());
  }

  private void scriptTwoRounds(FakeOpenAiProvider fake) {
    fake.script(
        fake.toolRound("call_1", "listTrustedIssuers", "{\"outcome\":\"age_over_18\"}", 1000, 200),
        fake.toolRound(
            "call_2",
            "getPolicyDocument",
            "{\"policyId\":\"" + GuardPolicies.POLICY_ID + "\",\"version\":\"1\"}",
            2000,
            300),
        fake.finalRound(candidate(), 3000, 400));
  }

  @Test
  void liveSessionFundsEachRoundAndSettlesAggregate() throws Exception {
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      scriptTwoRounds(fake);
      LivePlanner live =
          new LivePlanner(properties(fake), tools, Clock.systemUTC(), mapper,
              ledger(10_000_000));
      List<Long> estimates = new ArrayList<>();
      live.estimateLogSink = estimates;
      PlanningInvocation.install(
          new PlanningInvocation(caller("budget-ok"), properties(fake).maxToolCalls()));
      try {
        PlanningResult result = live.plan(intent(), "test-hash");
        assertThat(fake.requestCount()).isEqualTo(3);
        assertThat(result.usageTokens()).isEqualTo(6_900L);
        assertThat(result.toolCalls()).isEqualTo(2);
        assertThat(
                owner.queryForMap(
                    "SELECT requests_used, tokens_used, requests_reserved, tokens_reserved"
                        + " FROM ai_budget_day WHERE day = CURRENT_DATE"))
            .containsEntry("requests_used", 1)
            .containsEntry("tokens_used", 6_900L)
            .containsEntry("requests_reserved", 0)
            .containsEntry("tokens_reserved", 0L);
        assertThat(
                owner.queryForMap(
                    "SELECT state, settled_tokens FROM ai_call_lease LIMIT 1"))
            .containsEntry("state", "SETTLED")
            .containsEntry("settled_tokens", 6_900L);
        // Guard estimates meet or beat every real request body.
        assertThat(estimates).hasSize(3);
        for (int i = 0; i < 3; i++) {
          assertThat(estimates.get(i))
              .isGreaterThanOrEqualTo((long) fake.requestBodyBytes().get(i));
        }
      } finally {
        PlanningInvocation.clear();
        live.estimateLogSink = null;
      }
    }
  }

  @Test
  void unqualifiedModelDeniedBeforeAnySpend() throws Exception {
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      PlanningProperties props = properties(fake);
      props.setAllowedModels(List.of("some-other-model"));
      LivePlanner live =
          new LivePlanner(props, tools, Clock.systemUTC(), mapper, ledger(10_000_000));
      PlanningInvocation.install(new PlanningInvocation(caller("budget-model"), 8));
      try {
        assertThatThrownBy(() -> live.plan(intent(), "test-hash"))
            .isInstanceOf(PlanningUnavailableException.class)
            .hasMessageContaining("not qualified");
      } finally {
        PlanningInvocation.clear();
      }
      assertThat(fake.requestCount()).isZero();
      assertThat(
              owner.queryForObject("SELECT COUNT(*) FROM ai_budget_day", Integer.class))
          .isZero();
    }
  }

  @Test
  void sdkRetriesRefusedBeforeAnySpend() throws Exception {
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      PlanningProperties props = properties(fake);
      props.setMaxRetries(1);
      LivePlanner live =
          new LivePlanner(props, tools, Clock.systemUTC(), mapper, ledger(10_000_000));
      PlanningInvocation.install(new PlanningInvocation(caller("budget-retry"), 8));
      try {
        assertThatThrownBy(() -> live.plan(intent(), "test-hash"))
            .isInstanceOf(PlanningUnavailableException.class)
            .hasMessageContaining("maxRetries=0");
      } finally {
        PlanningInvocation.clear();
      }
      assertThat(fake.requestCount()).isZero();
      assertThat(
              owner.queryForObject("SELECT COUNT(*) FROM ai_budget_day", Integer.class))
          .isZero();
    }
  }

  @Test
  void overCapAdmissionDeniedBeforeAnySpend() throws Exception {
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      PlanningProperties props = properties(fake);
      props.setMaxTranscriptBytes(100);
      LivePlanner live =
          new LivePlanner(props, tools, Clock.systemUTC(), mapper, ledger(10_000_000));
      PlanningInvocation.install(new PlanningInvocation(caller("budget-cap"), 8));
      try {
        assertThatThrownBy(() -> live.plan(intent(), "test-hash"))
            .isInstanceOf(PlanningUnavailableException.class)
            .hasMessageContaining("transcript");
      } finally {
        PlanningInvocation.clear();
      }
      assertThat(fake.requestCount()).isZero();
      assertThat(
              owner.queryForObject("SELECT COUNT(*) FROM ai_budget_day", Integer.class))
          .isZero();
    }
  }

  @Test
  void midLoopBudgetAbortSettlesExactSpend() throws Exception {
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      scriptTwoRounds(fake);
      PlanningProperties props = properties(fake);
      // Fund round one plus a token: any round-two top-up is denied.
      long firstBytes =
          BudgetGuardedChatModel.estimateBytes(
              List.of(
                  new SystemMessage(PlanningPrompts.system()),
                  new UserMessage(PlanningPrompts.user(intent()))),
              tools.callbacks());
      long firstBound =
          BudgetGuardedChatModel.roundBound(firstBytes, props.maxTokens(), props.maxRetries());
      LivePlanner live =
          new LivePlanner(props, tools, Clock.systemUTC(), mapper, ledger(firstBound + 1));
      PlanningInvocation.install(new PlanningInvocation(caller("budget-abort"), 8));
      try {
        assertThatThrownBy(() -> live.plan(intent(), "test-hash"))
            .isInstanceOf(PlanningUnavailableException.class)
            .hasMessageContaining("budget exhausted");
      } finally {
        PlanningInvocation.clear();
      }
      // One round fired; the abort settles its exact reported usage.
      assertThat(fake.requestCount()).isEqualTo(1);
      assertThat(
              owner.queryForMap(
                  "SELECT requests_used, tokens_used, requests_reserved, tokens_reserved"
                      + " FROM ai_budget_day WHERE day = CURRENT_DATE"))
          .containsEntry("requests_used", 1)
          .containsEntry("tokens_used", 1_200L)
          .containsEntry("requests_reserved", 0)
          .containsEntry("tokens_reserved", 0L);
      assertThat(owner.queryForMap("SELECT state, settled_tokens FROM ai_call_lease LIMIT 1"))
          .containsEntry("state", "SETTLED")
          .containsEntry("settled_tokens", 1_200L);
    }
  }

  @Test
  void failedRoundBurnsFundedEstimate() throws Exception {
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      fake.script(
          fake.toolRound(
              "call_1", "listTrustedIssuers", "{\"outcome\":\"age_over_18\"}", 1000, 200),
          FakeOpenAiProvider.failure(500, "fake outage"));
      LivePlanner live =
          new LivePlanner(properties(fake), tools, Clock.systemUTC(), mapper,
              ledger(10_000_000));
      PlanningInvocation.install(new PlanningInvocation(caller("budget-fail"), 8));
      try {
        assertThatThrownBy(() -> live.plan(intent(), "test-hash"))
            .isInstanceOf(PlanningUnavailableException.class)
            .hasMessageContaining("did not return a candidate");
      } finally {
        PlanningInvocation.clear();
      }
      assertThat(fake.requestCount()).isEqualTo(2);
      var lease =
          owner.queryForMap(
              "SELECT state, estimated_tokens, settled_tokens FROM ai_call_lease LIMIT 1");
      assertThat(lease.get("state")).isEqualTo("UNCERTAIN");
      assertThat(lease.get("settled_tokens")).isEqualTo(lease.get("estimated_tokens"));
      assertThat(
              owner.queryForObject(
                  "SELECT tokens_used FROM ai_budget_day WHERE day = CURRENT_DATE", Long.class))
          .isEqualTo((Long) lease.get("estimated_tokens"));
    }
  }

  @Test
  void budgetDefaultsStayDisarmed() {
    assertThat(defaultProperties.liveEnabled()).isFalse();
    assertThat(defaultProperties.allowedModels()).isEmpty();
    assertThat(defaultProperties.maxTranscriptBytes()).isPositive();
    assertThat(defaultProperties.maxTokens()).isPositive();
  }

  @Test
  void zeroBudgetDeniedBeforeAnySpend() throws Exception {
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      LivePlanner live =
          new LivePlanner(properties(fake), tools, Clock.systemUTC(), mapper, ledger(0));
      PlanningInvocation.install(new PlanningInvocation(caller("budget-zero"), 8));
      try {
        assertThatThrownBy(() -> live.plan(intent(), "test-hash"))
            .isInstanceOf(PlanningUnavailableException.class)
            .hasMessageContaining("budget exhausted");
      } finally {
        PlanningInvocation.clear();
      }
      assertThat(fake.requestCount()).isZero();
      // The denied reservation rolls back: no day row, no lease.
      assertThat(owner.queryForObject("SELECT COUNT(*) FROM ai_budget_day", Integer.class))
          .isZero();
      assertThat(owner.queryForObject("SELECT COUNT(*) FROM ai_call_lease", Integer.class))
          .isZero();
    }
  }

  @Test
  void shortLeaseRefusedBeforeAnySpend() throws Exception {
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      PlanningProperties props = properties(fake);
      // Lease 5s cannot cover the 10s provider timeout plus margin.
      LivePlanner live =
          new LivePlanner(props, tools, Clock.systemUTC(), mapper, ledger(10_000_000, 5));
      PlanningInvocation.install(new PlanningInvocation(caller("budget-lease"), 8));
      try {
        assertThatThrownBy(() -> live.plan(intent(), "test-hash"))
            .isInstanceOf(PlanningUnavailableException.class)
            .hasMessageContaining("lease");
      } finally {
        PlanningInvocation.clear();
      }
      assertThat(fake.requestCount()).isZero();
      assertThat(owner.queryForObject("SELECT COUNT(*) FROM ai_budget_day", Integer.class))
          .isZero();
    }
  }

  @Test
  void growingTranscriptRefusedBeforeSecondHttp() throws Exception {
    // Calibrate on a full session: the transcript strictly grows, so
    // capping a second run at its own first-round estimate refuses
    // round two before any second request leaves.
    long firstEstimate;
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      scriptTwoRounds(fake);
      LivePlanner live =
          new LivePlanner(properties(fake), tools, Clock.systemUTC(), mapper,
              ledger(10_000_000));
      List<Long> estimates = new ArrayList<>();
      live.estimateLogSink = estimates;
      PlanningInvocation.install(
          new PlanningInvocation(caller("budget-grow-cal"), 8));
      try {
        live.plan(intent(), "test-hash");
      } finally {
        PlanningInvocation.clear();
        live.estimateLogSink = null;
      }
      assertThat(estimates).hasSize(3);
      assertThat(estimates.get(1)).isGreaterThan(estimates.get(0));
      firstEstimate = estimates.get(0);
    }
    owner.update("DELETE FROM ai_call_lease");
    owner.update("DELETE FROM ai_budget_day");
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      scriptTwoRounds(fake);
      PlanningProperties props = properties(fake);
      props.setMaxTranscriptBytes(Math.toIntExact(firstEstimate));
      LivePlanner live =
          new LivePlanner(props, tools, Clock.systemUTC(), mapper, ledger(10_000_000));
      PlanningInvocation.install(new PlanningInvocation(caller("budget-grow"), 8));
      try {
        assertThatThrownBy(() -> live.plan(intent(), "test-hash"))
            .isInstanceOf(PlanningUnavailableException.class)
            .hasMessageContaining("transcript");
      } finally {
        PlanningInvocation.clear();
      }
      // One round fired; the refusal settles its exact reported usage.
      assertThat(fake.requestCount()).isEqualTo(1);
      assertThat(owner.queryForMap("SELECT state, settled_tokens FROM ai_call_lease LIMIT 1"))
          .containsEntry("state", "SETTLED")
          .containsEntry("settled_tokens", 1_200L);
    }
  }

  @Test
  void timeoutBurnsFundedEstimateAsUncertain() throws Exception {
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      fake.script(
          FakeOpenAiProvider.delayed(fake.finalRound(candidate(), 100, 20), 3_000));
      PlanningProperties props = properties(fake);
      props.setTimeout(Duration.ofSeconds(1));
      LivePlanner live =
          new LivePlanner(props, tools, Clock.systemUTC(), mapper, ledger(10_000_000));
      PlanningInvocation.install(new PlanningInvocation(caller("budget-timeout"), 8));
      try {
        assertThatThrownBy(() -> live.plan(intent(), "test-hash"))
            .isInstanceOf(PlanningUnavailableException.class)
            .hasMessageContaining("did not return a candidate");
      } finally {
        PlanningInvocation.clear();
      }
      assertThat(fake.requestCount()).isEqualTo(1);
      var lease =
          owner.queryForMap(
              "SELECT state, estimated_tokens, settled_tokens FROM ai_call_lease LIMIT 1");
      assertThat(lease.get("state")).isEqualTo("UNCERTAIN");
      assertThat(lease.get("settled_tokens")).isEqualTo(lease.get("estimated_tokens"));
    }
  }

  @Test
  void missingUsageBurnsConservativeReservation() throws Exception {
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      fake.script(fake.finalRoundWithoutUsage(candidate()));
      LivePlanner live =
          new LivePlanner(properties(fake), tools, Clock.systemUTC(), mapper,
              ledger(10_000_000));
      PlanningInvocation.install(new PlanningInvocation(caller("budget-nousage"), 8));
      try {
        PlanningResult result = live.plan(intent(), "test-hash");
        assertThat(result.mode()).isEqualTo(PlanningMode.LIVE);
      } finally {
        PlanningInvocation.clear();
      }
      assertThat(fake.requestCount()).isEqualTo(1);
      // No usage reported anywhere: the funded reservation settles in
      // full as spent, never refunded as uncertain-free.
      var lease =
          owner.queryForMap(
              "SELECT state, estimated_tokens, settled_tokens FROM ai_call_lease LIMIT 1");
      assertThat(lease.get("state")).isEqualTo("SETTLED");
      assertThat(lease.get("settled_tokens")).isEqualTo(lease.get("estimated_tokens"));
      assertThat(
              owner.queryForObject(
                  "SELECT tokens_used FROM ai_budget_day WHERE day = CURRENT_DATE", Long.class))
          .isEqualTo((Long) lease.get("estimated_tokens"));
    }
  }

  @Test
  void runawayToolLoopEndsAtRoundCapWithFiniteSettle() throws Exception {
    // The model never stops emitting tool calls; the guard's own
    // round cap — independent of the tool budget, which the raw echo
    // tool never charges — ends the session with bounded requests
    // and exact completed spend.
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      fake.script(
          fake.toolRound("c1", "echo", "{\"x\":\"a\"}", 100, 50),
          fake.toolRound("c2", "echo", "{\"x\":\"b\"}", 200, 50),
          fake.toolRound("c3", "echo", "{\"x\":\"c\"}", 300, 50),
          fake.toolRound("c4", "echo", "{\"x\":\"d\"}", 400, 50),
          fake.finalRound("done", 500, 60));
      PlanningProperties props = properties(fake);
      props.setMaxToolCalls(1);
      AiBudgetService service = ledger(10_000_000);
      java.util.concurrent.atomic.AtomicReference<java.util.UUID> lease =
          new java.util.concurrent.atomic.AtomicReference<>();
      BudgetGuardedChatModel.SessionUsage session = new BudgetGuardedChatModel.SessionUsage();
      org.springframework.ai.tool.ToolCallback echo = echoTool();
      long firstBytes =
          BudgetGuardedChatModel.estimateBytes(
              List.of(new UserMessage("hi")), List.of(echo));
      long firstBound =
          BudgetGuardedChatModel.roundBound(firstBytes, props.maxTokens(), props.maxRetries());
      org.springframework.ai.openai.OpenAiChatModel inner =
          org.springframework.ai.openai.OpenAiChatModel.builder()
              .options(
                  org.springframework.ai.openai.OpenAiChatOptions.builder()
                      .baseUrl(fake.baseUrl())
                      .apiKey("test-only-key")
                      .model("fake-model")
                      .timeout(Duration.ofSeconds(5))
                      .maxRetries(0)
                      .maxTokens(8000)
                      .temperature(0.0)
                      .seed(7)
                      .build())
              .build();
      assertThatThrownBy(
              () -> service.execute(
                  java.util.UUID.randomUUID(),
                  firstBound,
                  new AiBudgetService.LeaseAwareCall<
                      org.springframework.ai.chat.model.ChatResponse>() {
                    @Override
                    public void lease(java.util.UUID leaseId) {
                      lease.set(leaseId);
                    }

                    @Override
                    public org.springframework.ai.chat.model.ChatResponse invoke() {
                      org.springframework.ai.chat.model.ChatModel guarded =
                          new BudgetGuardedChatModel(
                              inner,
                              service,
                              lease,
                              props,
                              List.of(echo),
                              session,
                              firstBound,
                              null);
                      return org.springframework.ai.chat.client.ChatClient.create(guarded)
                          .prompt()
                          .user("hi")
                          .toolCallbacks(List.of(echo))
                          .options(
                              org.springframework.ai.openai.OpenAiChatOptions.builder()
                                  .maxTokens(8000)
                                  .temperature(0.0)
                                  .seed(7))
                          .call()
                          .chatResponse();
                    }

                    @Override
                    public long usageOf(org.springframework.ai.chat.model.ChatResponse result) {
                      return session.complete() ? session.accumulated() : -1;
                    }
                  }))
          .isInstanceOf(PlanningUnavailableException.class)
          .hasMessageContaining("round budget");
      assertThat(fake.requestCount()).isEqualTo(2);
      assertThat(owner.queryForMap("SELECT state, settled_tokens FROM ai_call_lease LIMIT 1"))
          .containsEntry("state", "SETTLED")
          .containsEntry("settled_tokens", 400L);
      long envelope =
          BudgetGuardedChatModel.sessionBound(
              props.maxToolCalls(),
              props.maxTranscriptBytes(),
              props.maxTokens(),
              props.maxRetries());
      assertThat(400L).isLessThan(envelope);
    }
  }

  private static org.springframework.ai.tool.ToolCallback echoTool() {
    org.springframework.ai.tool.definition.ToolDefinition definition =
        org.springframework.ai.tool.definition.DefaultToolDefinition.builder()
            .name("echo")
            .description("Returns ok.")
            .inputSchema(
                "{\"type\":\"object\",\"properties\":{\"x\":{\"type\":\"string\"}},"
                    + "\"additionalProperties\":false}")
            .build();
    return new org.springframework.ai.tool.ToolCallback() {
      @Override
      public org.springframework.ai.tool.definition.ToolDefinition getToolDefinition() {
        return definition;
      }

      @Override
      public String call(String toolInput) {
        return "{\"ok\":true}";
      }

      @Override
      public String call(
          String toolInput, org.springframework.ai.chat.model.ToolContext toolContext) {
        return "{\"ok\":true}";
      }
    };
  }
}
