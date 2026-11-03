package dev.sovra.planning;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.messages.Message;
import org.springframework.ai.chat.messages.ToolResponseMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.tool.ToolCallback;

/**
 * Per-attempt budget guard around the chat model (PROD-012). The pinned
 * framework calls {@link #call} once per tool round with no internal
 * recursion ({@code PlannerAdapterSemanticsTests} pins that seam), so
 * this decorator sees every normal round: it measures the full prompt,
 * refuses over-cap transcripts before any bytes leave, pre-funds each
 * further round through {@link AiBudgetService#topUp}, heartbeats the
 * lease, and accumulates per-round usage. SDK retries stay invisible
 * below this seam, so metered runs require {@code maxRetries=0} and
 * plan-level retry stays an honest re-reserved 503.
 */
final class BudgetGuardedChatModel implements ChatModel {

  /**
   * Qualified-model sizing assumptions (see {@code ai-budgets.md}).
   * They hold only for models on the configured allowlist after
   * tokenizer and completion-cap observation — never universal.
   */
  static final long MIN_BYTES_PER_TOKEN = 1;
  static final long OVERHEAD_TOKENS = 512;

  /** JSON framing allowance: request envelope plus per-message keys. */
  static final long REQUEST_FRAMING_BYTES = 2048;
  static final long PER_MESSAGE_BYTES = 128;

  /** Per-round provider usage, shared with the settle step. */
  static final class SessionUsage {
    private long accumulated;
    private boolean complete = true;

    void add(long roundTotal) {
      accumulated += roundTotal;
    }

    void omitted() {
      complete = false;
    }

    long accumulated() {
      return accumulated;
    }

    boolean complete() {
      return complete;
    }
  }

  private final ChatModel delegate;
  private final AiBudgetService ledger;
  private final AtomicReference<java.util.UUID> lease;
  private final PlanningProperties properties;
  private final List<ToolCallback> callbacks;
  private final SessionUsage usage;
  private final List<Long> estimateLog;
  private final long admittedBound;
  private int round;
  private long reservedSoFar;

  BudgetGuardedChatModel(
      ChatModel delegate,
      AiBudgetService ledger,
      AtomicReference<java.util.UUID> lease,
      PlanningProperties properties,
      List<ToolCallback> callbacks,
      SessionUsage usage,
      long admittedBound,
      List<Long> estimateLog) {
    this.delegate = delegate;
    this.ledger = ledger;
    this.lease = lease;
    this.properties = properties;
    this.callbacks = callbacks;
    this.usage = usage;
    this.admittedBound = admittedBound;
    this.estimateLog = estimateLog;
    this.reservedSoFar = admittedBound;
  }

  @Override
  public ChatResponse call(Prompt prompt) {
    java.util.UUID leaseId = lease.get();
    if (leaseId == null) {
      throw new IllegalStateException("guarded call without a budget lease");
    }
    round++;
    if (round > maxRounds()) {
      // Finite session cap independent of the tool budget: a tool
      // round that errors without charging (or any loop the tool
      // budget does not see) still ends here, before further spend.
      // Refused before any provider contact for this round.
      throw new AiBudgetService.BudgetAbort(
          abortSettleValue(),
          new PlanningUnavailableException(
              "planning round budget exceeded; no candidate produced"));
    }
    long bytes = estimateBytes(prompt.getInstructions(), callbacks);
    if (estimateLog != null) {
      estimateLog.add(bytes);
    }
    if (bytes > properties.maxTranscriptBytes()) {
      throw new AiBudgetService.BudgetAbort(
          abortSettleValue(),
          new PlanningUnavailableException("planning transcript exceeds its bound"));
    }
    long bound = roundBound(bytes, properties.maxTokens(), properties.maxRetries());
    try {
      if (round == 1) {
        // Same inputs the admission measured; the catch-up only pays
        // if the client ever injects hidden first-round content.
        long catchUp = Math.max(0, bound - admittedBound);
        ledger.topUp(leaseId, catchUp);
        reservedSoFar += catchUp;
      } else {
        ledger.topUp(leaseId, bound);
        reservedSoFar += bound;
      }
    } catch (AiBudgetExhaustedException e) {
      throw new AiBudgetService.BudgetAbort(
          abortSettleValue(), new PlanningUnavailableException("live-AI budget exhausted"));
    }
    ChatResponse response = delegate.call(prompt);
    Long roundTotal = roundUsage(response);
    if (roundTotal == null) {
      usage.omitted();
    } else {
      usage.add(roundTotal);
    }
    return response;
  }

  private long abortSettleValue() {
    return usage.complete() ? usage.accumulated() : reservedSoFar;
  }

  private static Long roundUsage(ChatResponse response) {
    try {
      if (response.getMetadata() == null || response.getMetadata().getUsage() == null) {
        return null;
      }
      Integer total = response.getMetadata().getUsage().getTotalTokens();
      // The adapter masks omitted provider usage as zero (pinned in
      // PlannerAdapterSemanticsTests); a completed round always spends
      // prompt tokens, so zero means unreported and settles the funded
      // reservation instead of a misleading exact zero.
      return total == null || total == 0 ? null : total.longValue();
    } catch (RuntimeException e) {
      return null;
    }
  }

  /**
   * Worst-case tokens for one round at the measured prompt size: prompt
   * bytes at the qualified-model ratio, plus the provider-honored
   * completion cap and per-request overhead, times the attempt
   * multiplicity. The retries gate holds the multiplier at one.
   */
  static long roundBound(long promptBytes, int maxTokens, int maxRetries) {
    long promptTokens = (promptBytes + MIN_BYTES_PER_TOKEN - 1) / MIN_BYTES_PER_TOKEN;
    return (promptTokens + maxTokens + OVERHEAD_TOKENS) * (1L + maxRetries);
  }

  /** Max provider rounds per session: one tool round per budgeted tool call, plus the final round. */
  int maxRounds() {
    return properties.maxToolCalls() + 1;
  }

  /**
   * Finite worst-case session funding at the configured caps: every
   * round at the full transcript byte cap, each with the full
   * provider-honored completion cap and overhead, over the finite
   * round cap, times the attempt multiplicity. The retries gate holds
   * the multiplier at one; settled actuals stay inside this envelope
   * unless a sizing assumption breaks (recorded loud, never hidden).
   */
  static long sessionBound(int maxToolCalls, int maxTranscriptBytes, int maxTokens, int maxRetries) {
    return (long) (maxToolCalls + 1) * roundBound(maxTranscriptBytes, maxTokens, maxRetries);
  }

  /**
   * Conservative serialized size of one outbound attempt: every message
   * (text, tool calls, tool results), every tool definition, and fixed
   * framing allowances. String sizes count the JSON-escaped wire form
   * — quotes, backslashes, control characters, supplementary
   * codepoints (12 bytes each: surrogate halves escape separately),
   * and unpaired surrogates (6 each) — so raw UTF-8 lengths would
   * undercount adversarial tool output. Must meet or beat the real
   * request body; the budget tests assert that against the fake
   * provider on every round, including adversarial-content and
   * supplementary/unpaired-Unicode cases.
   */
  static long estimateBytes(List<Message> messages, List<ToolCallback> callbacks) {
    long total = REQUEST_FRAMING_BYTES;
    if (messages != null) {
      for (Message message : messages) {
        total += PER_MESSAGE_BYTES + bytes(message.getText());
        if (message instanceof AssistantMessage assistant) {
          for (AssistantMessage.ToolCall call : assistant.getToolCalls()) {
            total += bytes(call.id()) + bytes(call.type()) + bytes(call.name())
                + bytes(call.arguments());
          }
        } else if (message instanceof ToolResponseMessage tool) {
          for (ToolResponseMessage.ToolResponse response : tool.getResponses()) {
            total += bytes(response.id()) + bytes(response.name())
                + bytes(response.responseData());
          }
        }
      }
    }
    if (callbacks != null) {
      for (ToolCallback callback : callbacks) {
        total += PER_MESSAGE_BYTES;
        try {
          var definition = callback.getToolDefinition();
          total += bytes(definition.name()) + bytes(definition.description())
              + bytes(definition.inputSchema());
        } catch (RuntimeException e) {
          total += REQUEST_FRAMING_BYTES;
        }
      }
    }
    return total;
  }

  /**
   * Wire size of a string inside a JSON request body: UTF-8 bytes plus
   * the escape expansion the pinned provider serializer adds. Quotes
   * and backslashes gain a backslash; control characters gain at
   * least one byte (backslash-letter style) and up to five (U+00XX
   * style), so all count the worst-case six. Supplementary
   * codepoints count twelve: the OpenAI SDK writes UTF-8 directly
   * with {@code COMBINE_UNICODE_SURROGATES_IN_UTF8=false} (pinned
   * by test), so each surrogate half escapes as a six-byte U+XXXX sequence (6+6), not raw
   * 4-byte UTF-8 — twelve also covers the combined 4-byte form if
   * that flag ever flips. Unpaired surrogates count six (one U+XXXX escape), covering the replacement forms too.
   * BMP text counts raw UTF-8 ({@code ESCAPE_NON_ASCII=false},
   * pinned). Counts the worst case per codepoint, so adversarial
   * tool output never outgrows the estimate.
   */
  private static long bytes(String text) {
    if (text == null) {
      return 0;
    }
    long total = 0;
    for (int i = 0; i < text.length(); ) {
      char c = text.charAt(i);
      if (c == '"' || c == '\\') {
        total += 2;
        i++;
      } else if (c < 0x20) {
        total += 6;
        i++;
      } else if (c < 0x80) {
        total += 1;
        i++;
      } else if (Character.isHighSurrogate(c)) {
        if (i + 1 < text.length() && Character.isLowSurrogate(text.charAt(i + 1))) {
          total += 12;
          i += 2;
        } else {
          total += 6;
          i++;
        }
      } else if (Character.isLowSurrogate(c)) {
        total += 6;
        i++;
      } else {
        total += Character.toString(c).getBytes(StandardCharsets.UTF_8).length;
        i++;
      }
    }
    return total;
  }

  // The client builds request options from the model defaults: without
  // delegation the prompt reaches the provider adapter with foreign
  // options and the call fails before any HTTP (probe-observed).
  @Override
  public ChatOptions getDefaultOptions() {
    return delegate.getDefaultOptions();
  }

  @Override
  public ChatOptions getOptions() {
    return delegate.getOptions();
  }
}
