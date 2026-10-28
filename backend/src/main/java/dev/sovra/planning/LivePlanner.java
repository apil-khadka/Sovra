package dev.sovra.planning;

import dev.sovra.authz.ForbiddenException;
import dev.sovra.guard.CandidatePlan;
import dev.sovra.guard.PlanParser;
import dev.sovra.issuance.TrustUnavailableException;
import java.time.Clock;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
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

  private final PlanningProperties properties;
  private final PlanningTools tools;
  private final Clock clock;
  private final ObjectMapper mapper;

  private volatile OpenAiChatModel cached;

  public LivePlanner(
      PlanningProperties properties, PlanningTools tools, Clock clock, ObjectMapper mapper) {
    this.properties = properties;
    this.tools = tools;
    this.clock = clock;
    this.mapper = mapper;
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
   * becomes a candidate.
   */
  public PlanningResult plan(PlanningIntent intent, String toolHash) {
    if (!properties.liveReady()) {
      throw new PlanningUnavailableException("live planning is not configured");
    }
    String system = PlanningPrompts.system();
    String user = PlanningPrompts.user(intent);
    if (system.length() + user.length() > properties.maxPromptChars()) {
      throw new PlanningUnavailableException("planning prompt exceeds its bound");
    }
    PlanningInvocation invocation =
        PlanningInvocation.current()
            .orElseThrow(
                () -> new IllegalStateException("live planning outside an authorized invocation"));
    long started = clock.millis();
    try {
      ChatClient client = ChatClient.create(chatModel());
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
    } catch (RuntimeException e) {
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
      return total == null ? null : total.longValue();
    } catch (RuntimeException e) {
      return null;
    }
  }

  /** Visible for status reporting. */
  List<String> toolNames() {
    return tools.callbacks().stream().map(c -> c.getToolDefinition().name()).toList();
  }
}
