package dev.sovra.extraction;

import java.util.Map;

/**
 * Observed extraction result: raw field strings exactly as the
 * engine read them, plus the engine's confidence in [0, 1].
 * Normalization and digests are derived downstream, never here.
 */
public record ExtractionOutcome(Map<String, String> observed, double confidence) {

  public ExtractionOutcome {
    if (observed == null || observed.isEmpty()) {
      throw new ExtractionInvalidException("extraction produced no fields");
    }
    if (!(confidence >= 0 && confidence <= 1)) {
      throw new ExtractionInvalidException("confidence must be 0..1");
    }
    observed = Map.copyOf(observed);
  }
}
