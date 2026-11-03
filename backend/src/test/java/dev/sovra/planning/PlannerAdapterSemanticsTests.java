package dev.sovra.planning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.ToolContext;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.openai.OpenAiChatOptions;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.DefaultToolDefinition;
import org.springframework.ai.tool.definition.ToolDefinition;

/**
 * Pinned provider-adapter seams (PROD-012): the budget guard relies on
 * the model call being a single attempt, on the tool loop staying
 * visible to an outer decorator, on final usage aggregating every
 * round, and on SDK retries staying invisible — each pinned here
 * against the fake provider so a framework upgrade fails loudly
 * instead of silently voiding the envelope.
 */
class PlannerAdapterSemanticsTests {

  private static ToolCallback echo() {
    ToolDefinition definition =
        DefaultToolDefinition.builder()
            .name("echo")
            .description("Returns its input unchanged.")
            .inputSchema(
                "{\"type\":\"object\",\"properties\":{\"x\":{\"type\":\"string\"}},"
                    + "\"additionalProperties\":false}")
            .build();
    return new ToolCallback() {
      @Override
      public ToolDefinition getToolDefinition() {
        return definition;
      }

      @Override
      public String call(String toolInput) {
        return "{\"ok\":true}";
      }

      @Override
      public String call(String toolInput, ToolContext toolContext) {
        return "{\"ok\":true}";
      }
    };
  }

  private static OpenAiChatModel model(FakeOpenAiProvider fake, int maxRetries) {
    return OpenAiChatModel.builder()
        .options(
            OpenAiChatOptions.builder()
                .baseUrl(fake.baseUrl())
                .apiKey("test-only-key")
                .model("fake-model")
                .timeout(Duration.ofSeconds(5))
                .maxRetries(maxRetries)
                .maxTokens(8000)
                .temperature(0.0)
                .seed(7)
                .build())
        .build();
  }

  private static ChatModel counting(OpenAiChatModel inner, AtomicInteger calls) {
    return new ChatModel() {
      @Override
      public ChatResponse call(Prompt prompt) {
        calls.incrementAndGet();
        return inner.call(prompt);
      }

      @Override
      public org.springframework.ai.chat.prompt.ChatOptions getDefaultOptions() {
        return inner.getDefaultOptions();
      }

      @Override
      public org.springframework.ai.chat.prompt.ChatOptions getOptions() {
        return inner.getOptions();
      }
    };
  }

  @Test
  void directModelCallIsOneAttemptWithUnexecutedToolCalls() throws Exception {
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      fake.script(fake.toolRound("call_1", "echo", "{\"x\":\"a\"}", 100, 50));
      Prompt prompt =
          new Prompt(
              List.of(new UserMessage("hi")),
              OpenAiChatOptions.builder().toolCallbacks(echo()).build());
      ChatResponse response = model(fake, 0).call(prompt);
      assertThat(fake.requestCount()).isEqualTo(1);
      assertThat(response.getResult().getOutput().getToolCalls()).hasSize(1);
      assertThat(response.getResult().getOutput().getToolCalls().get(0).name())
          .isEqualTo("echo");
    }
  }

  @Test
  void toolLoopIssuesOneHttpCallPerRoundAndAggregatesUsage() throws Exception {
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      fake.script(
          fake.toolRound("call_1", "echo", "{\"x\":\"a\"}", 100, 50),
          fake.toolRound("call_2", "echo", "{\"x\":\"b\"}", 200, 50),
          fake.finalRound("done", 300, 60));
      AtomicInteger calls = new AtomicInteger();
      ChatClient client = ChatClient.create(counting(model(fake, 0), calls));
      ChatResponse response =
          client
              .prompt()
              .system("sys")
              .user("hi")
              .toolCallbacks(List.of(echo()))
              .options(OpenAiChatOptions.builder().maxTokens(8000).temperature(0.0).seed(7))
              .call()
              .chatResponse();
      // Every round visible to the outer decorator: no bypass.
      assertThat(calls.get()).isEqualTo(3);
      assertThat(fake.requestCount()).isEqualTo(3);
      assertThat(fake.observed())
          .allMatch(o -> o.path().equals("/v1/chat/completions"));
      // Final usage is the sum across rounds, not the last round.
      assertThat(response.getMetadata().getUsage().getPromptTokens()).isEqualTo(600);
      assertThat(response.getMetadata().getUsage().getCompletionTokens()).isEqualTo(160);
      assertThat(response.getMetadata().getUsage().getTotalTokens()).isEqualTo(760);
      // The transcript grows round over round.
      assertThat(fake.requestBodyBytes()).isEqualTo(List.of(359, 563, 767));
    }
  }

  @Test
  void sdkRetriesAreInvisibleBelowTheDecorator() throws Exception {
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      fake.script(
          FakeOpenAiProvider.failure(500, "fake outage"),
          fake.finalRound("recovered", 100, 20));
      AtomicInteger calls = new AtomicInteger();
      ChatClient client = ChatClient.create(counting(model(fake, 1), calls));
      ChatResponse response =
          client
              .prompt()
              .system("sys")
              .user("hi")
              .options(OpenAiChatOptions.builder().maxTokens(8000).temperature(0.0).seed(7))
              .call()
              .chatResponse();
      assertThat(calls.get()).isEqualTo(1);
      assertThat(fake.requestCount()).isEqualTo(2);
      assertThat(response.getResult().getOutput().getText()).isEqualTo("recovered");
    }
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      fake.script(FakeOpenAiProvider.failure(500, "fake outage"));
      assertThatThrownBy(
              () ->
                  ChatClient.create(model(fake, 0))
                      .prompt()
                      .system("sys")
                      .user("hi")
                      .options(
                          OpenAiChatOptions.builder().maxTokens(8000).temperature(0.0).seed(7))
                      .call()
                      .chatResponse())
          .isInstanceOf(RuntimeException.class);
      assertThat(fake.requestCount()).isEqualTo(1);
    }
  }

  @Test
  void overCapPromptAbortsBeforeAnyProviderContact() throws Exception {
    PlanningProperties properties = new PlanningProperties();
    properties.setMaxTranscriptBytes(10);
    AtomicInteger delegateCalls = new AtomicInteger();
    ChatModel never =
        new ChatModel() {
          @Override
          public ChatResponse call(Prompt prompt) {
            delegateCalls.incrementAndGet();
            throw new IllegalStateException("must not reach the provider");
          }
        };
    BudgetGuardedChatModel guarded =
        new BudgetGuardedChatModel(
            never,
            // Null ledger: the cap check precedes any ledger use.
            null,
            new java.util.concurrent.atomic.AtomicReference<>(java.util.UUID.randomUUID()),
            properties,
            List.of(),
            new BudgetGuardedChatModel.SessionUsage(),
            0,
            null);
    Prompt prompt = new Prompt(List.of(new UserMessage("this prompt is far over ten bytes")));
    assertThatThrownBy(() -> guarded.call(prompt))
        .isInstanceOf(AiBudgetService.BudgetAbort.class);
    assertThat(delegateCalls.get()).isZero();
  }

  @Test
  void jsonEscapingExpansionStaysInsideEstimate() throws Exception {
    // Adversarial tool output: every JSON escape class — quotes,
    // backslashes, short escapes, U+00XX controls, multibyte text.
    String adversarial = "\"quoted\" \\ backslash \n newline \t tab \r return \u0001 \u001f café";
    long estimate =
        BudgetGuardedChatModel.estimateBytes(List.of(new UserMessage(adversarial)), List.of());
    tools.jackson.databind.ObjectMapper mapper = new tools.jackson.databind.ObjectMapper();
    java.util.Map<String, Object> request =
        java.util.Map.of(
            "model", "fake-model",
            "messages",
                List.of(java.util.Map.of("role", "user", "content", adversarial)));
    long wire =
        mapper.writeValueAsString(request).getBytes(java.nio.charset.StandardCharsets.UTF_8)
            .length;
    assertThat(estimate).isGreaterThanOrEqualTo(wire);
    // The expansion is actually counted: raw UTF-8 alone falls short.
    long raw = adversarial.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
    long counted =
        estimate
            - BudgetGuardedChatModel.REQUEST_FRAMING_BYTES
            - BudgetGuardedChatModel.PER_MESSAGE_BYTES;
    assertThat(counted).isGreaterThan(raw);
  }

  @Test
  void supplementaryUnicodeStaysInsideProviderRequest() throws Exception {
    // 3000 emoji: the old UTF-16 loop counted 2 bytes each (lone-half
    // replacement '?') vs 4-byte UTF-8, and the real provider wire is
    // 12 bytes each (surrogate halves escape separately with
    // COMBINE_UNICODE_SURROGATES_IN_UTF8=false) — so even 4-byte
    // counting undercounts the wire by ~22KB here.
    String emoji = new String(Character.toChars(0x1F600));
    String text = emoji.repeat(3000);
    long estimate =
        BudgetGuardedChatModel.estimateBytes(List.of(new UserMessage(text)), List.of());
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      fake.script(fake.finalRound("ok", 100, 20));
      Prompt prompt =
          new Prompt(
              List.of(new UserMessage(text)),
              OpenAiChatOptions.builder().maxTokens(8000).temperature(0.0).seed(7).build());
      model(fake, 0).call(prompt);
      assertThat(fake.requestCount()).isEqualTo(1);
      long real = fake.requestBodyBytes().get(0);
      assertThat(estimate).isGreaterThanOrEqualTo(real);
      // Pin the wire shape: escaped halves, not raw UTF-8.
      assertThat(fake.observed().get(0).body()).contains("\\uD83D\\uDE00");
      long fourByteCounting =
          BudgetGuardedChatModel.REQUEST_FRAMING_BYTES
              + BudgetGuardedChatModel.PER_MESSAGE_BYTES
              + 4L * 3000;
      assertThat(fourByteCounting).isLessThan(real);
    }
  }

  @Test
  void unpairedSurrogatesStayInsideProviderRequest() throws Exception {
    // Malformed input: lone highs, lone lows, a swapped pair (two
    // unpaired halves), and a trailing high. Each unpaired half
    // escapes as one U+XXXX sequence (6 bytes) on the provider wire, not the
    // 1-byte '?' Java's UTF-8 encoder substitutes.
    String malformed =
        "\uD83D".repeat(1000) + "\uDE00".repeat(1000) + "\uDE00\uD83D" + "A\uD83D";
    long estimate =
        BudgetGuardedChatModel.estimateBytes(List.of(new UserMessage(malformed)), List.of());
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      fake.script(fake.finalRound("ok", 100, 20));
      Prompt prompt =
          new Prompt(
              List.of(new UserMessage(malformed)),
              OpenAiChatOptions.builder().maxTokens(8000).temperature(0.0).seed(7).build());
      model(fake, 0).call(prompt);
      assertThat(fake.requestCount()).isEqualTo(1);
      long real = fake.requestBodyBytes().get(0);
      assertThat(estimate).isGreaterThanOrEqualTo(real);
      String body = fake.observed().get(0).body();
      assertThat(body).contains("\\uD83D");
      assertThat(body).contains("\\uDE00");
      long oneBytePerHalf =
          BudgetGuardedChatModel.REQUEST_FRAMING_BYTES
              + BudgetGuardedChatModel.PER_MESSAGE_BYTES
              + malformed.length();
      assertThat(oneBytePerHalf).isLessThan(real);
    }
  }

  @Test
  void unicodeCorpusStaysInsideProviderRequest() throws Exception {
    // Bounded corpus across every wire class: ASCII, quotes and
    // backslashes, short and U+00XX controls, BMP two- and
    // three-byte text, supplementary codepoints (musical, emoji,
    // maximum), unpaired halves in each position, and a mixed
    // adversarial string. Each case fires the real adapter against
    // the fake provider; the estimate must meet every real body.
    String mixed =
        "A" + new String(Character.toChars(0x1F600)) + "B\"\n\\é\u0001\uD83D";
    List<String> corpus =
        List.of(
            "hello",
            "\"quoted\" \\ backslash",
            "\n \t \r \u0001 \u001f",
            "café naïve",
            "Ω 中 €",
            new String(Character.toChars(0x1D11E)),
            new String(Character.toChars(0x1F600)),
            new String(Character.toChars(0x10FFFF)),
            "A\uD83DB",
            "A\uDE00B",
            "\uDE00\uD83D",
            mixed);
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      for (int i = 0; i < corpus.size(); i++) {
        fake.script(fake.finalRound("ok", 100, 20));
      }
      org.springframework.ai.openai.OpenAiChatModel chat = model(fake, 0);
      for (String text : corpus) {
        long estimate =
            BudgetGuardedChatModel.estimateBytes(List.of(new UserMessage(text)), List.of());
        Prompt prompt =
            new Prompt(
                List.of(new UserMessage(text)),
                OpenAiChatOptions.builder().maxTokens(8000).temperature(0.0).seed(7).build());
        chat.call(prompt);
        long real = fake.requestBodyBytes().get(fake.requestCount() - 1);
        assertThat(estimate).isGreaterThanOrEqualTo(real);
      }
      assertThat(fake.requestCount()).isEqualTo(corpus.size());
      // Pin the split wire shape: BMP text stays raw UTF-8
      // (ESCAPE_NON_ASCII=false) while supplementary escapes.
      assertThat(fake.observed().get(3).body()).contains("café");
      assertThat(fake.observed().get(3).body()).doesNotContain("\\u00E9");
      assertThat(fake.observed().get(6).body()).contains("\\uD83D\\uDE00");
    }
  }

  @Test
  void omittedProviderUsageArrivesAsZero() throws Exception {
    try (FakeOpenAiProvider fake = new FakeOpenAiProvider()) {
      fake.script(fake.finalRoundWithoutUsage("done"));
      ChatResponse response =
          ChatClient.create(model(fake, 0))
              .prompt()
              .system("sys")
              .user("hi")
              .options(OpenAiChatOptions.builder().maxTokens(8000).temperature(0.0).seed(7))
              .call()
              .chatResponse();
      Integer total = null;
      if (response.getMetadata() != null && response.getMetadata().getUsage() != null) {
        total = response.getMetadata().getUsage().getTotalTokens();
      }
      // Pinned masking: omission arrives as zero, never distinct —
      // so the budget path treats zero as unknown and burns the
      // funded reservation instead of settling an exact zero.
      assertThat(total == null || total == 0).isTrue();
    }
  }

  @Test
  void sessionBoundIsFiniteAndCoversEveryRound() {
    long perRound = BudgetGuardedChatModel.roundBound(32768, 8000, 0);
    assertThat(perRound).isEqualTo(32768 + 8000 + 512);
    long session = BudgetGuardedChatModel.sessionBound(8, 32768, 8000, 0);
    assertThat(session).isEqualTo(9 * perRound);
    assertThat(session).isEqualTo(371_520L);
  }
}
