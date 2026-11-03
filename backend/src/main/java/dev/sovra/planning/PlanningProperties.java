package dev.sovra.planning;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Live-planning configuration (SOV-013, OD-02). Everything sensitive or
 * account-specific arrives from the environment — {@code SOVRA_AI_BASE_URL},
 * {@code SOVRA_AI_MODEL}, {@code SOVRA_AI_API_KEY} — and defaults to
 * unset, so a default boot can never reach a model provider. Live calls
 * additionally require the explicit {@code SOVRA_AI_LIVE_ENABLED=true}
 * arming flag. Budgets are finite and fail closed (NFR-03).
 */
@ConfigurationProperties(prefix = "sovra.ai")
public class PlanningProperties {

  /** Arming flag: live model calls happen only when explicitly true. */
  private boolean liveEnabled = false;

  /** Operator-configured chat endpoint; no default (never model-directed). */
  private String baseUrl;

  /** Provider credential from environment only; never logged or returned. */
  private String apiKey;

  /** Account-verified model id; no default until OD-02 smoke passes. */
  private String model;

  /** Max tool callbacks per planning request (SEC-16, SEC-19). */
  private int maxToolCalls = 8;

  /** Single provider-call deadline (SEC-19, SEC-22). */
  private Duration timeout = Duration.ofSeconds(10);

  /**
   * Provider retries, not tool retries (SEC-19). Defaults to zero:
   * SDK retries fire below the budget guard with unknowable
   * server-side billing, so metered live calls require
   * {@code maxRetries=0} and refuse anything else at admission.
   */
  private int maxRetries = 0;

  /**
   * Provider-side output token cap (NFR-03). Reasoning models spend
   * this budget on reasoning before answering (OD-02 measured 2119
   * reasoning tokens on one planning turn), so the default leaves
   * headroom while staying finite and fail-closed.
   */
  private int maxTokens = 8000;

  /** Local bound on the prompt and on the raw model output (SEC-18). */
  private int maxPromptChars = 8000;

  /** Deterministic sampling for reproducible runs (NFR-10). */
  private double temperature = 0.0;

  /** Fixed seed recorded with every live run (NFR-10). */
  private int seed = 7;

  /**
   * Model ids qualified for metered live planning (PROD-012). The
   * token envelope's byte ratio, per-request overhead, and completion-cap
   * assumptions are stated per qualified model, never universal: an
   * empty list denies every live call, and a model joins only after its
   * tokenizer behavior and max-tokens completion cap are observed.
   */
  private java.util.List<String> allowedModels = java.util.List.of();

  /**
   * Outward byte cap per provider attempt (PROD-012). The budget guard
   * serializes the full prompt — messages, tool definitions, and JSON
   * framing allowance — before each outbound call and fails the run
   * closed past this bound, so unbounded tool results can never grow a
   * request without limit. No extra model request fires on breach.
   */
  private int maxTranscriptBytes = 32768;

  public boolean liveEnabled() {
    return liveEnabled;
  }

  public void setLiveEnabled(boolean liveEnabled) {
    this.liveEnabled = liveEnabled;
  }

  public String baseUrl() {
    return baseUrl;
  }

  public void setBaseUrl(String baseUrl) {
    this.baseUrl = baseUrl;
  }

  public String apiKey() {
    return apiKey;
  }

  public void setApiKey(String apiKey) {
    this.apiKey = apiKey;
  }

  public String model() {
    return model;
  }

  public void setModel(String model) {
    this.model = model;
  }

  public int maxToolCalls() {
    return maxToolCalls;
  }

  public void setMaxToolCalls(int maxToolCalls) {
    this.maxToolCalls = maxToolCalls;
  }

  public Duration timeout() {
    return timeout;
  }

  public void setTimeout(Duration timeout) {
    this.timeout = timeout;
  }

  public int maxRetries() {
    return maxRetries;
  }

  public void setMaxRetries(int maxRetries) {
    this.maxRetries = maxRetries;
  }

  public int maxTokens() {
    return maxTokens;
  }

  public void setMaxTokens(int maxTokens) {
    this.maxTokens = maxTokens;
  }

  public int maxPromptChars() {
    return maxPromptChars;
  }

  public void setMaxPromptChars(int maxPromptChars) {
    this.maxPromptChars = maxPromptChars;
  }

  public double temperature() {
    return temperature;
  }

  public void setTemperature(double temperature) {
    this.temperature = temperature;
  }

  public int seed() {
    return seed;
  }

  public void setSeed(int seed) {
    this.seed = seed;
  }

  public java.util.List<String> allowedModels() {
    return allowedModels;
  }

  public void setAllowedModels(java.util.List<String> allowedModels) {
    this.allowedModels = allowedModels == null ? java.util.List.of() : allowedModels;
  }

  public int maxTranscriptBytes() {
    return maxTranscriptBytes;
  }

  public void setMaxTranscriptBytes(int maxTranscriptBytes) {
    this.maxTranscriptBytes = maxTranscriptBytes;
  }

  /** True only when the operator armed live planning with full credentials. */
  public boolean liveReady() {
    return liveEnabled
        && baseUrl != null && !baseUrl.isBlank()
        && apiKey != null && !apiKey.isBlank()
        && model != null && !model.isBlank();
  }

  /** Safe for status responses: presence only, never values. */
  public boolean credentialsPresent() {
    return baseUrl != null && !baseUrl.isBlank()
        && apiKey != null && !apiKey.isBlank()
        && model != null && !model.isBlank();
  }
}
