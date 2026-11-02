package dev.sovra.planning;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Fleet-wide live-AI budgets (PROD-012). All limits default to
 * zero, which disarms live spending twice: the arming flag
 * ({@code SOVRA_AI_LIVE_ENABLED}) gates the call path, and a zero
 * budget denies every reservation. Production with live AI
 * requires all three limits positive (entry-gate enforced).
 */
@ConfigurationProperties(prefix = "sovra.ai-budget")
public class AiBudgetProperties {

  /** Max live requests per UTC day across the fleet. */
  private int dailyRequests = 0;

  /** Max live tokens per UTC day across the fleet. */
  private long dailyTokens = 0;

  /** Max concurrent live calls across the fleet. */
  private int maxConcurrency = 0;

  /** Lease lifetime: covers the provider timeout plus retries and parse. */
  private int leaseSeconds = 120;

  public int dailyRequests() {
    return dailyRequests;
  }

  public void setDailyRequests(int dailyRequests) {
    this.dailyRequests = dailyRequests;
  }

  public long dailyTokens() {
    return dailyTokens;
  }

  public void setDailyTokens(long dailyTokens) {
    this.dailyTokens = dailyTokens;
  }

  public int maxConcurrency() {
    return maxConcurrency;
  }

  public void setMaxConcurrency(int maxConcurrency) {
    this.maxConcurrency = maxConcurrency;
  }

  public int leaseSeconds() {
    return leaseSeconds;
  }

  public void setLeaseSeconds(int leaseSeconds) {
    this.leaseSeconds = leaseSeconds;
  }
}
