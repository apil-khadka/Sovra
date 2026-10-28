package dev.sovra.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Deployment mode (SOV-040). {@code demo} runs the synthetic fixture
 * stack; {@code production} refuses synthetic issuers, keys, profiles,
 * and seed configuration on every path (startup scan, activation gate,
 * verification gate, signer selection, person-verified quorum). Unknown
 * values fail boot: a misspelled mode must never silently run as demo.
 */
@Component
public class SovraMode {

  private final boolean production;

  public SovraMode(@Value("${sovra.mode:demo}") String mode) {
    if ("production".equals(mode)) {
      this.production = true;
    } else if ("demo".equals(mode)) {
      this.production = false;
    } else {
      throw new IllegalArgumentException(
          "sovra.mode must be demo or production, was: " + mode);
    }
  }

  public boolean isProduction() {
    return production;
  }
}
