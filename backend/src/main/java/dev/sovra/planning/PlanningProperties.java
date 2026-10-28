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

  /** Bounded provider retries, not tool retries (SEC-19). */
  private int maxRetries = 1;

  /** Provider-side output token cap (NFR-03). */
  private int maxTokens = 2000;

  /** Local bound on the prompt and on the raw model output (SEC-18). */
  private int maxPromptChars = 8000;

  /** Deterministic sampling for reproducible runs (NFR-10). */
  private double temperature = 0.0;

  /** Fixed seed recorded with every live run (NFR-10). */
  private int seed = 7;

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
