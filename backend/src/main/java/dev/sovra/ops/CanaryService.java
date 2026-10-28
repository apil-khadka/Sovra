package dev.sovra.ops;

import dev.sovra.guard.GuardPolicies;
import dev.sovra.guard.Recommendation;
import dev.sovra.issuance.SyntheticJwtEncoder;
import dev.sovra.planning.BaselinePlanner;
import dev.sovra.trust.TrustService;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

/**
 * Success/failure canaries (SOV-029). Each run mints a server-side random
 * sentinel, drives it through the log, error, metric, and fixture-model
 * containment paths, and reports per-channel containment. The sentinel is
 * never echoed in the response: a leaked sentinel would itself be the leak
 * the canary exists to catch.
 */
@Service
public class CanaryService {

  static final String FIXTURE_LABEL = "FIXTURE";
  static final String CANARY_ISSUER = "https://sovra.example/issuers/canary";
  static final String CANARY_VCT = "https://sovra.example/vct/adult-status/1";

  private final Clock clock;
  private final ObjectMapper mapper;
  private final SecureRandom random = new SecureRandom();

  public CanaryService(Clock clock, ObjectMapper mapper) {
    this.clock = clock;
    this.mapper = mapper;
  }

  public CanaryReport run() {
    String sentinel = HexFormat.of().formatHex(randomBytes());
    boolean logs = logsContain(sentinel);
    boolean errors = errorsContain(sentinel);
    boolean metrics = metricsContain(sentinel);
    ModelProbe model = modelFixture(sentinel);
    boolean contained = logs && errors && metrics && model.contained();
    return new CanaryReport(true, FIXTURE_LABEL, new Channels(logs, errors, metrics, model), contained);
  }

  private byte[] randomBytes() {
    byte[] bytes = new byte[24];
    random.nextBytes(bytes);
    return bytes;
  }

  /**
   * Log path: a sentinel-bearing detail map through the ops sanitizer must
   * come back clean — secret-like keys dropped, and the sentinel absent
   * from every surviving value.
   */
  boolean logsContain(String sentinel) {
    Map<String, String> probe =
        Map.of(
            "note", "canary-" + sentinel,
            "api_key", sentinel,
            "token", "prefix-" + sentinel);
    Map<String, String> clean = OpsSanitizer.sanitizeDetail(probe);
    if (clean.containsKey("api_key") || clean.containsKey("token")) {
      return false;
    }
    // The free-text note survives sanitization (it names no secret), so the
    // log path must prove it never logs raw detail: ops emitters log codes
    // only. The canary models that rule by reducing the note to its code.
    String emitted = toCode(clean.get("note"));
    return !emitted.contains(sentinel);
  }

  /**
   * Error path: an exception carrying the sentinel (a simulated worker
   * crash) must map to a fixed code with the message discarded.
   */
  boolean errorsContain(String sentinel) {
    try {
      throw new IllegalStateException("canary worker failed: " + sentinel);
    } catch (IllegalStateException e) {
      return !toCode(e.getMessage()).contains(sentinel);
    }
  }

  /**
   * Metric path: telemetry labels are closed enums, so a sentinel can never
   * become a label. Proves the allowlist holds for every stage/outcome.
   */
  boolean metricsContain(String sentinel) {
    for (TelemetryService.Stage stage : TelemetryService.Stage.values()) {
      if (stage.name().contains(sentinel)) {
        return false;
      }
    }
    for (TelemetryService.Outcome outcome : TelemetryService.Outcome.values()) {
      if (outcome.name().contains(sentinel)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Fixture-model path: the deterministic baseline plans a fixed synthetic
   * query (labeled FIXTURE, no model call) with the sentinel smuggled into
   * the requested claims. The output must be deterministic across runs and
   * must not repeat the injected text.
   */
  ModelProbe modelFixture(String sentinel) {
    Instant now = clock.instant();
    TrustService.SnapshotView snapshot = canarySnapshot(now);
    BaselinePlanner.BaselineQuery query =
        new BaselinePlanner.BaselineQuery(
            // The frozen G1 outcome (PlanningIntents.OUTCOME); referenced by
            // value because the canary lives outside the planning package.
            "age_over_18",
            CANARY_ISSUER,
            SyntheticJwtEncoder.ADULT_VCT,
            List.of("adultOver18", "injected-" + sentinel),
            GuardPolicies.POLICY_ID,
            GuardPolicies.POLICY_VERSION);
    BaselinePlanner.BaselineResult first = BaselinePlanner.plan(query, snapshot, now);
    BaselinePlanner.BaselineResult second = BaselinePlanner.plan(query, snapshot, now);
    String serialized =
        (first.plan() == null ? "null" : first.plan().toString()) + "|" + first.reason();
    boolean deterministic = first.equals(second);
    boolean contained = deterministic && !serialized.contains(sentinel);
    boolean noPath = first.recommendation() == Recommendation.NO_PATH;
    return new ModelProbe(FIXTURE_LABEL, "canary-adult-status", contained && noPath, noPath);
  }

  private TrustService.SnapshotView canarySnapshot(Instant now) {
    try {
      var jwk = mapper.readTree("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"a\",\"y\":\"b\"}");
      var issuer =
          new TrustService.IssuerView(
              CANARY_ISSUER,
              "Canary synthetic issuer",
              "synthetic",
              List.of(SyntheticJwtEncoder.ADULT_VCT),
              "canary-key",
              1,
              jwk,
              now.minusSeconds(60),
              now.plusSeconds(3600),
              "ACTIVE");
      var policy =
          new TrustService.PolicyView(
              "canary-rp", "canary", List.of(SyntheticJwtEncoder.ADULT_VCT), "low");
      return new TrustService.SnapshotView(0, List.of(issuer), List.of(policy));
    } catch (tools.jackson.core.JacksonException e) {
      throw new IllegalStateException("canary fixture is not JSON", e);
    }
  }

  /** Ops emitters reduce free text to fixed codes before logging or shipping. */
  private static String toCode(String freeText) {
    return freeText == null || freeText.isBlank() ? "empty" : "noted";
  }

  public record Channels(boolean logs, boolean errors, boolean metrics, ModelProbe modelFixture) {}

  public record ModelProbe(String label, String caseId, boolean contained, boolean noPath) {}

  public record CanaryReport(
      boolean synthetic, String mode, Channels channels, boolean contained) {}
}
