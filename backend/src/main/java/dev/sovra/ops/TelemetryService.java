package dev.sovra.ops;

import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.TenantMismatchException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Sanitized stage timings and reason metrics (SOV-029). Services record one
 * sample per flow stage: a fixed stage name, a fixed outcome, and a duration.
 * No request content, identity data, or error text is ever recorded, so
 * aggregates are safe to return to the owning tenant. Storage is bounded and
 * in-memory; crash-explicit like the alert clocks, and the durable audit log
 * remains the system of record for decisions.
 */
@Service
public class TelemetryService {

  /** Flow stages with timing evidence, in flow order. */
  public enum Stage {
    ISSUANCE_ISSUE,
    CONSENT_CREATE,
    CONSENT_DECIDE,
    VERIFICATION_VERIFY
  }

  /** Fixed terminal outcomes; exception text is never stored. */
  public enum Outcome {
    OK,
    DENIED,
    REJECTED,
    ERROR
  }

  static final int MAX_TENANTS = 1024;
  static final int MAX_SAMPLES_PER_STAGE = 512;

  private final JdbcTemplate tenant;
  private final ConcurrentHashMap<TenantStage, StageStats> stats = new ConcurrentHashMap<>();

  public TelemetryService(@Qualifier("tenantJdbcTemplate") JdbcTemplate tenant) {
    this.tenant = tenant;
  }

  /**
   * Times one stage execution, classifying the terminal outcome from the
   * thrown exception: authorization denials to DENIED, the caller's
   * validation exceptions to REJECTED, anything else to ERROR. Normal
   * return records OK. The exception itself is never retained.
   */
  public <T> T time(
      UUID tenantId, Stage stage, Set<Class<? extends RuntimeException>> rejections,
      Supplier<T> work) {
    long start = System.nanoTime();
    try {
      T result = work.get();
      record(tenantId, stage, elapsedMs(start), Outcome.OK);
      return result;
    } catch (ForbiddenException | TenantMismatchException e) {
      record(tenantId, stage, elapsedMs(start), Outcome.DENIED);
      throw e;
    } catch (RuntimeException e) {
      record(tenantId, stage, elapsedMs(start), classify(e, rejections));
      throw e;
    }
  }

  private static Outcome classify(RuntimeException e, Set<Class<? extends RuntimeException>> rejections) {
    for (Class<? extends RuntimeException> type : rejections) {
      if (type.isInstance(e)) {
        return Outcome.REJECTED;
      }
    }
    return Outcome.ERROR;
  }

  /** Records one sample; drops tenants past the bound instead of growing. */
  public void record(UUID tenantId, Stage stage, long durationMs, Outcome outcome) {
    if (tenantId == null || stage == null || outcome == null) {
      return;
    }
    TenantStage key = new TenantStage(tenantId, stage);
    StageStats existing = stats.get(key);
    if (existing == null) {
      if (stats.size() >= MAX_TENANTS * Stage.values().length) {
        return;
      }
      existing = stats.computeIfAbsent(key, k -> new StageStats());
    }
    existing.add(Math.max(0, durationMs), outcome);
  }

  /** Per-stage aggregates for one tenant; empty when nothing was recorded. */
  public Map<String, StageSummary> summary(UUID tenantId) {
    Map<String, StageSummary> out = new LinkedHashMap<>();
    for (Stage stage : Stage.values()) {
      StageStats stat = stats.get(new TenantStage(tenantId, stage));
      if (stat != null) {
        out.put(stage.name(), stat.summarize());
      }
    }
    return out;
  }

  /**
   * Reason metrics from the durable audit log (RLS applies): counts by
   * action, decision, and reason code for the caller's tenant. Actions and
   * codes are fixed identifiers, safe to report.
   */
  public List<Map<String, Object>> reasonCounts(UUID tenantId) {
    return tenant.query(
        "SELECT action, decision, reason_code, COUNT(*) AS n FROM audit_event"
            + " WHERE tenant_id = ? GROUP BY action, decision, reason_code"
            + " ORDER BY action, decision, reason_code",
        (rs, row) -> {
          Map<String, Object> entry = new LinkedHashMap<>();
          entry.put("action", rs.getString("action"));
          entry.put("decision", rs.getString("decision"));
          entry.put("reasonCode", rs.getString("reason_code"));
          entry.put("count", rs.getLong("n"));
          return entry;
        },
        tenantId);
  }

  private record TenantStage(UUID tenantId, Stage stage) {}

  /** Bounded ring of durations plus fixed outcome counters. */
  static final class StageStats {
    private final Deque<Long> samples = new ArrayDeque<>();
    private final EnumMap<Outcome, Long> outcomes = new EnumMap<>(Outcome.class);

    synchronized void add(long durationMs, Outcome outcome) {
      samples.addLast(durationMs);
      while (samples.size() > MAX_SAMPLES_PER_STAGE) {
        samples.removeFirst();
      }
      outcomes.merge(outcome, 1L, Long::sum);
    }

    synchronized StageSummary summarize() {
      List<Long> sorted = new ArrayList<>(samples);
      sorted.sort(Long::compareTo);
      Map<String, Long> counts = new LinkedHashMap<>();
      for (Outcome outcome : Outcome.values()) {
        counts.put(outcome.name(), outcomes.getOrDefault(outcome, 0L));
      }
      if (sorted.isEmpty()) {
        return new StageSummary(0, 0, 0, 0, counts);
      }
      return new StageSummary(
          sorted.size(),
          percentile(sorted, 50),
          percentile(sorted, 95),
          sorted.get(sorted.size() - 1),
          counts);
    }

    private static long percentile(List<Long> sorted, int pct) {
      int index = (int) Math.ceil((pct / 100.0) * sorted.size()) - 1;
      return sorted.get(Math.max(0, Math.min(index, sorted.size() - 1)));
    }
  }

  public record StageSummary(
      long count, long p50Ms, long p95Ms, long maxMs, Map<String, Long> outcomes) {}

  private static long elapsedMs(long startNanos) {
    return Math.max(0, (System.nanoTime() - startNanos) / 1_000_000);
  }
}
