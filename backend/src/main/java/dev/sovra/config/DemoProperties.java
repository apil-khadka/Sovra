package dev.sovra.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Public-demo admission boundary (SOV-027). When {@code syntheticOnly}
 * is true, the externally reachable ingestion endpoints — vault
 * object/version stores and quarantine admissions — reject
 * caller-supplied bytes with {@code 403 demo_synthetic_only}, even
 * for authenticated privileged callers. Reads, grants, verdicts and
 * promotion still work, so the demo serves server-seeded synthetic
 * fixtures but accepts no visitor uploads. Local development keeps
 * the default {@code false} so synthetic API tests can seal bytes;
 * the public-demo deployment profile sets
 * {@code SOVRA_DEMO_SYNTHETIC_ONLY=true}.
 */
@ConfigurationProperties(prefix = "sovra.demo")
public class DemoProperties {

  /** Arming flag: reject caller-supplied ingestion bytes when true. */
  private boolean syntheticOnly = false;

  public boolean syntheticOnly() {
    return syntheticOnly;
  }

  public void setSyntheticOnly(boolean syntheticOnly) {
    this.syntheticOnly = syntheticOnly;
  }
}
