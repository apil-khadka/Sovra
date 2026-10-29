package dev.sovra.ops;

import dev.sovra.audit.AuditSanitizer;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Final output gate for operations surfaces. Check details, canary
 * payloads, and any future free-text ops field pass through here: secret-like
 * keys are dropped, values are truncated, and non-scalar values are replaced
 * with a type tag so raw driver or framework objects never reach Jackson.
 * Key and truncation rules come from {@code AuditSanitizer}; only the
 * heterogeneous-object shape is ops-owned.
 */
public final class OpsSanitizer {

  private OpsSanitizer() {}

  public static Map<String, String> sanitizeDetail(Map<String, String> detail) {
    return AuditSanitizer.sanitize(detail);
  }

  /**
   * Sanitizes heterogeneous check detail: numbers, booleans, instants, and
   * enums pass through; strings truncate; anything else becomes a
   * {@code redacted:<type>} tag.
   */
  public static Map<String, Object> sanitizeObjects(Map<String, Object> detail) {
    Map<String, Object> clean = new LinkedHashMap<>();
    if (detail == null) {
      return clean;
    }
    for (Map.Entry<String, Object> entry : detail.entrySet()) {
      String key = entry.getKey();
      if (AuditSanitizer.sensitiveKey(key)) {
        continue;
      }
      Object value = entry.getValue();
      if (value == null) {
        clean.put(key, "");
      } else if (value instanceof String text) {
        clean.put(key, AuditSanitizer.truncate(text));
      } else if (value instanceof Number
          || value instanceof Boolean
          || value instanceof Instant
          || value instanceof Enum) {
        clean.put(key, value);
      } else {
        clean.put(key, "redacted:" + value.getClass().getSimpleName());
      }
    }
    return clean;
  }
}
