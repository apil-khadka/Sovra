package dev.sovra.planning;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import tools.jackson.databind.ObjectMapper;

/**
 * Controllable OpenAI-compatible chat provider for budget tests. Serves
 * scripted {@code chat.completion} payloads on any path ending in
 * {@code chat/completions}, records every request body for transcript
 * measurement, and injects failures to observe SDK retries. No new test
 * dependencies: JDK HTTP server plus the Jackson the backend ships.
 *
 * <p>Loopback only; never pointed at a real provider.
 */
final class FakeOpenAiProvider implements AutoCloseable {

  /** One scripted HTTP response, served FIFO per request. */
  record Scripted(int status, String body, long delayMs) {
    Scripted(int status, String body) {
      this(status, body, 0);
    }
  }

  /** One observed provider request. */
  record Observed(String path, String body, boolean authPresent) {}

  private final HttpServer server;
  private final ObjectMapper mapper = new ObjectMapper();
  private final Queue<Scripted> script = new ConcurrentLinkedQueue<>();
  private final List<Observed> observed = new CopyOnWriteArrayList<>();
  private final AtomicInteger sequence = new AtomicInteger();
  private volatile String unexpectedBody;

  FakeOpenAiProvider() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 32);
    server.createContext(
        "/",
        exchange -> {
          try {
            handle(exchange);
          } catch (Exception e) {
            fail(exchange, e);
          }
        });
    server.setExecutor(Executors.newCachedThreadPool());
    server.start();
  }

  /** Base URL to configure as {@code sovra.ai.base-url} (carries /v1). */
  String baseUrl() {
    return "http://127.0.0.1:" + server.getAddress().getPort() + "/v1";
  }

  /** Queue scripted responses, served FIFO. */
  void script(Scripted... responses) {
    script.addAll(List.of(responses));
  }

  List<Observed> observed() {
    return List.copyOf(observed);
  }

  int requestCount() {
    return observed.size();
  }

  /** A tool-call round with distinct usage, for aggregation checks. */
  Scripted toolRound(String callId, String name, String argumentsJson,
      int promptTokens, int completionTokens) {
    Map<String, Object> function = new LinkedHashMap<>();
    function.put("name", name);
    function.put("arguments", argumentsJson);
    Map<String, Object> call = new LinkedHashMap<>();
    call.put("id", callId);
    call.put("type", "function");
    call.put("function", function);
    Map<String, Object> message = new LinkedHashMap<>();
    message.put("role", "assistant");
    message.put("content", null);
    message.put("tool_calls", List.of(call));
    return completion(message, "tool_calls", promptTokens, completionTokens);
  }

  /** A final round carrying model content with distinct usage. */
  Scripted finalRound(String content, int promptTokens, int completionTokens) {
    Map<String, Object> message = new LinkedHashMap<>();
    message.put("role", "assistant");
    message.put("content", content);
    return completion(message, "stop", promptTokens, completionTokens);
  }

  /** A final round that omits the usage block, for unknown-spend settle. */
  Scripted finalRoundWithoutUsage(String content) {
    try {
      Map<String, Object> message = new LinkedHashMap<>();
      message.put("role", "assistant");
      message.put("content", content);
      Map<String, Object> choice = new LinkedHashMap<>();
      choice.put("index", 0);
      choice.put("message", message);
      choice.put("finish_reason", "stop");
      Map<String, Object> body = new LinkedHashMap<>();
      body.put("id", "chatcmpl-fake-" + sequence.incrementAndGet());
      body.put("object", "chat.completion");
      body.put("created", 1762000000L);
      body.put("model", "fake-model");
      body.put("choices", List.of(choice));
      return new Scripted(200, mapper.writeValueAsString(body));
    } catch (RuntimeException e) {
      throw new IllegalStateException("fake completion is not serializable", e);
    }
  }

  /** Serves a scripted response after a delay, for client-timeout tests. */
  static Scripted delayed(Scripted response, long delayMs) {
    return new Scripted(response.status(), response.body(), delayMs);
  }

  /** A retryable provider failure. */
  static Scripted failure(int status, String message) {
    String body =
        "{\"error\":{\"message\":\"" + message + "\",\"type\":\"server_error\",\"code\":null}}";
    return new Scripted(status, body);
  }

  private Scripted completion(
      Map<String, Object> message, String finishReason, int promptTokens, int completionTokens) {
    try {
      Map<String, Object> choice = new LinkedHashMap<>();
      choice.put("index", 0);
      choice.put("message", message);
      choice.put("finish_reason", finishReason);
      Map<String, Object> usage = new LinkedHashMap<>();
      usage.put("prompt_tokens", promptTokens);
      usage.put("completion_tokens", completionTokens);
      usage.put("total_tokens", promptTokens + completionTokens);
      Map<String, Object> body = new LinkedHashMap<>();
      body.put("id", "chatcmpl-fake-" + sequence.incrementAndGet());
      body.put("object", "chat.completion");
      body.put("created", 1762000000L);
      body.put("model", "fake-model");
      body.put("choices", List.of(choice));
      body.put("usage", usage);
      return new Scripted(200, mapper.writeValueAsString(body));
    } catch (RuntimeException e) {
      throw new IllegalStateException("fake completion is not serializable", e);
    }
  }

  private void handle(HttpExchange exchange) throws Exception {
    String requestBody =
        new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    boolean authPresent =
        exchange.getRequestHeaders().containsKey("Authorization");
    observed.add(new Observed(exchange.getRequestURI().getPath(), requestBody, authPresent));
    Scripted next = script.poll();
    if (next == null) {
      unexpectedBody = requestBody;
      byte[] body =
          "{\"error\":{\"message\":\"no scripted response\",\"type\":\"server_error\"}}"
              .getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().set("Content-Type", "application/json");
      exchange.sendResponseHeaders(500, body.length);
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(body);
      }
      return;
    }
    if (next.delayMs() > 0) {
      Thread.sleep(next.delayMs());
    }
    byte[] body = next.body().getBytes(StandardCharsets.UTF_8);
    exchange.getRequestBody().close();
    exchange.getResponseHeaders().set("Content-Type", "application/json");
    exchange.sendResponseHeaders(next.status(), body.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(body);
    }
  }

  private void fail(HttpExchange exchange, Exception e) {
    try {
      byte[] body = "fake provider failure".getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(500, body.length);
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(body);
      }
    } catch (IOException ignored) {
      // Best effort: the test already observes the missing response.
    }
  }

  /** Request body that arrived with no scripted response, or null. */
  String unexpectedBody() {
    return unexpectedBody;
  }

  List<Integer> requestBodyBytes() {
    List<Integer> sizes = new ArrayList<>();
    for (Observed o : observed) {
      sizes.add(o.body().getBytes(StandardCharsets.UTF_8).length);
    }
    return sizes;
  }

  @Override
  public void close() {
    server.stop(0);
  }
}
