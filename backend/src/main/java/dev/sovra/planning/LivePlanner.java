package dev.sovra.planning;

import dev.sovra.authz.ForbiddenException;
import dev.sovra.guard.CandidatePlan;
import dev.sovra.guard.PlanParser;
import dev.sovra.issuance.TrustUnavailableException;
import java.time.Clock;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.openai.OpenAiChatOptions;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Live planning through the OpenAI-compatible chat adapter (SOV-013,
 * FR-05, IF-04). Runs only when the operator armed live planning with
 * a full endpoint/model/credential triple; every provider fault —
 * timeouts, throttles, truncated streams, malformed output, tool
 * overruns — becomes an explicit unavailable result, never invented
 * evidence (FR-12, SEC-19). Authorization denials propagate as 403.
 */
@Service
public class LivePlanner {

  private static final Logger log = LoggerFactory.getLogger(LivePlanner.class);

  /**
   * Local processing margin inside the lease adequacy check: one
   * provider timeout plus this many seconds must fit in the
   * configured lease, covering tool execution, parsing, and the
   * next heartbeat top-up between provider attempts.
   */
  static final long LEASE_PROCESSING_MARGIN_SECONDS = 30;

  private final PlanningProperties properties;
  private final PlanningTools tools;
  private final Clock clock;
  private final ObjectMapper mapper;
  private final AiBudgetService budgets;

  private volatile OpenAiChatModel cached;

  /**
   * Test seam: when non-null, the guard records its per-round byte
   * estimates here so tests can prove each estimate met or beat the
   * real request body. Production leaves it null.
   */
  volatile List<Long> estimateLogSink;

  public LivePlanner(
      PlanningProperties properties,
      PlanningTools tools,
      Clock clock,
      ObjectMapper mapper,
      AiBudgetService budgets) {
    this.properties = properties;
    this.tools = tools;
    this.clock = clock;
    this.mapper = mapper;
    this.budgets = budgets;
  }

  /**
   * Builds the chat model from operator configuration only. Package
   * visible so tests prove construction without touching a network.
   */
  OpenAiChatModel chatModel() {
    OpenAiChatModel model = cached;
    if (model == null) {
      synchronized (this) {
        model = cached;
        if (model == null) {
          model =
              OpenAiChatModel.builder()
                  .options(
                      OpenAiChatOptions.builder()
                          .baseUrl(properties.baseUrl())
                          .apiKey(properties.apiKey())
                          .model(properties.model())
                          .timeout(properties.timeout())
                          .maxRetries(properties.maxRetries())
                          .maxTokens(properties.maxTokens())
                          .temperature(properties.temperature())
                          .seed(properties.seed())
                          .build())
                  .build();
          cached = model;
        }
      }
    }
    return model;
  }

  /**
   * Runs one live planning call with the bounded read-only tools. The
   * caller must have installed a {@link PlanningInvocation}; the raw
   * model output is strictly parsed and bounded (SEC-18) before it
   * becomes a candidate. The session runs inside a fleet-wide budget
   * reservation (PROD-012): the first round's worst case is funded up
   * front, each further round pre-funds its own worst case through the
   * per-attempt guard, and pre-call aborts settle exact spend. Only
   * failures after provider contact — which cannot prove no charge —
   * burn the funded estimate as uncertain.
   */
  public PlanningResult plan(PlanningIntent intent, String toolHash) {
    if (!properties.liveReady()) {
      throw new PlanningUnavailableException("live planning is not configured");
    }
    if (!properties.allowedModels().contains(properties.model())) {
      throw new PlanningUnavailableException("live planning model is not qualified");
    }
    if (properties.maxRetries() != 0) {
      // SDK retries fire below the per-attempt guard with unknowable
      // server-side billing; metered runs refuse them. Plan-level
      // retry stays available as an honest re-reserved 503.
      throw new PlanningUnavailableException("live planning requires maxRetries=0");
    }
    long leastLease = properties.timeout().toSeconds() + LEASE_PROCESSING_MARGIN_SECONDS;
    if (budgets.leaseSeconds() < leastLease) {
      // The guard heartbeats the lease before every round, so the
      // lease must outlive one full provider timeout plus local
      // tool execution, parsing, and the next top-up — never the
      // whole session. A shorter lease would let the sweeper burn
      // a healthy in-flight call as uncertain.
      throw new PlanningUnavailableException(
          "live-AI lease is shorter than one provider timeout plus processing margin");
    }
    String system = PlanningPrompts.system();
    String user = PlanningPrompts.user(intent);
    if (system.length() + user.length() > properties.maxPromptChars()) {
      throw new PlanningUnavailableException("planning prompt exceeds its bound");
    }
    long firstBytes =
        BudgetGuardedChatModel.estimateBytes(
            List.of(new SystemMessage(system), new UserMessage(user)), tools.callbacks());
    if (firstBytes > properties.maxTranscriptBytes()) {
      throw new PlanningUnavailableException("planning transcript exceeds its bound");
    }
    PlanningInvocation invocation =
        PlanningInvocation.current()
            .orElseThrow(
                () -> new IllegalStateException("live planning outside an authorized invocation"));
    // First-round worst case at the measured prompt size; later rounds
    // top up from the same measurer inside the guard. The settle step
    // replaces the funding with provider-reported usage when every
    // round reported it.
    long firstBound =
        BudgetGuardedChatModel.roundBound(
            firstBytes, properties.maxTokens(), properties.maxRetries());
    AtomicReference<UUID> lease = new AtomicReference<>();
    BudgetGuardedChatModel.SessionUsage sessionUsage = new BudgetGuardedChatModel.SessionUsage();
    try {
      return budgets.execute(
          invocation.caller().tenantId(),
          firstBound,
          new AiBudgetService.LeaseAwareCall<PlanningResult>() {
            @Override
            public void lease(UUID leaseId) {
              lease.set(leaseId);
            }

            @Override
            public PlanningResult invoke() {
              return doPlan(intent, toolHash, invocation, system, user, lease, sessionUsage,
                  firstBound);
            }

            @Override
            public long usageOf(PlanningResult result) {
              if (!sessionUsage.complete() || result.usageTokens() == null) {
                return -1;
              }
              return result.usageTokens();
            }
          });
    } catch (AiBudgetExhaustedException e) {
      log.warn("live planning denied by budget: {}", e.getMessage());
      throw new PlanningUnavailableException("live-AI budget exhausted");
    } catch (PlanningUnavailableException | ForbiddenException
        | InvalidPlanningException | TrustUnavailableException e) {
      throw e;
    } catch (Exception e) {
      throw new PlanningUnavailableException("model provider did not return a candidate", e);
    }
  }

  private PlanningResult doPlan(
      PlanningIntent intent,
      String toolHash,
      PlanningInvocation invocation,
      String system,
      String user,
      AtomicReference<UUID> lease,
      BudgetGuardedChatModel.SessionUsage sessionUsage,
      long admittedBound) {
    long started = clock.millis();
    try {
      ChatModel guarded =
          new BudgetGuardedChatModel(
              chatModel(), budgets, lease, properties, tools.callbacks(), sessionUsage,
              admittedBound, estimateLogSink);
      ChatClient client = ChatClient.create(guarded);
      ChatResponse response =
          client
              .prompt()
              .system(system)
              .user(user)
              .toolCallbacks(tools.callbacks())
              .options(
                  OpenAiChatOptions.builder()
                      .maxTokens(properties.maxTokens())
                      .temperature(properties.temperature())
                      .seed(properties.seed()))
              .call()
              .chatResponse();
      String content = response.getResult().getOutput().getText();
      if (content == null || content.length() > properties.maxPromptChars()) {
        throw new PlanningUnavailableException("model output exceeds its bound");
      }
      CandidatePlan plan = parseStrict(content);
      Long tokens = usage(response);
      long latency = Math.max(0, clock.millis() - started);
      return PlanningResult.live(
          plan,
          plan.recommendation(),
          "live candidate; untrusted until the guard accepts it",
          properties.model(),
          toolHash,
          invocation.usedCalls(),
          latency,
          tokens);
    } catch (PlanningUnavailableException | ForbiddenException
        | InvalidPlanningException | TrustUnavailableException e) {
      throw e;
    } catch (AiBudgetService.BudgetAbort abort) {
      // Pre-call refusals carry their exact settle value to the
      // ledger step; wrapping them here would burn the funded
      // estimate as uncertain instead of settling completed spend.
      throw abort;
    } catch (RuntimeException e) {
      // The tool loop may wrap a guard refusal in a framework
      // exception; unwrap it so the ledger still settles exact
      // completed spend instead of burning the funding.
      for (Throwable t = e; t != null; t = t.getCause()) {
        if (t instanceof AiBudgetService.BudgetAbort abort) {
          throw abort;
        }
      }
      // Provider faults of every kind — timeouts, throttles, refused
      // connections, truncated streams — end the run as unavailable.
      // The detail is logged, never returned (no upstream text leaks).
      log.warn("live planning call failed without a candidate", e);
      throw new PlanningUnavailableException("model provider did not return a candidate", e);
    }
  }

  /**
   * Strict candidate parsing (SEC-18): the model output must be exactly
   * one JSON object in the guard plan shape. Malformed JSON, extra
   * members, unknown enums, and oversized output fail the run as
   * unavailable — conversion never establishes authorization.
   */
  private CandidatePlan parseStrict(String content) {
    JsonNode root;
    try {
      root = mapper.readTree(content);
    } catch (RuntimeException e) {
      throw new PlanningUnavailableException("model output is not JSON");
    }
    try {
      return PlanParser.parsePlan(root);
    } catch (RuntimeException e) {
      throw new PlanningUnavailableException("model output is not a valid candidate plan");
    }
  }

  /** Sanitized usage evidence: token counts only, never prompt text. */
  private static Long usage(ChatResponse response) {
    try {
      if (response.getMetadata() == null || response.getMetadata().getUsage() == null) {
        return null;
      }
      Integer total = response.getMetadata().getUsage().getTotalTokens();
      // Adapter-zero means the provider omitted usage (a completed
      // call always spends prompt tokens); report unreported so the
      // settle step burns the funded reservation, never an exact zero.
      return total == null || total == 0 ? null : total.longValue();
    } catch (RuntimeException e) {
      return null;
    }
  }

  /** Visible for status reporting. */
  List<String> toolNames() {
    return tools.callbacks().stream().map(c -> c.getToolDefinition().name()).toList();
  }
}
