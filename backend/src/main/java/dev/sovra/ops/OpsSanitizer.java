package dev.sovra.ops;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Final output gate for operations surfaces. Check details, canary
 * payloads, and any future free-text ops field pass through here: secret-like
 * keys are dropped, values are truncated, and non-scalar values are replaced
 * with a type tag so raw driver or framework objects never reach Jackson.
 * Mirrors the {@code AuditService} minimization rules for ops-owned output.
 */
public final class OpsSanitizer {

  static final int MAX_VALUE_CHARS = 500;

  private static final Pattern SENSITIVE_KEY =
      Pattern.compile(
          ".*(password|passwd|secret|token|api[_-]?key|private[_-]?key|ssn|social[_-]?security"
              + "|dob|birth|passport|credential_|proof_|jwk|seed|mnemonic).*",
          Pattern.CASE_INSENSITIVE);

  private OpsSanitizer() {}

  public static Map<String, String> sanitizeDetail(Map<String, String> detail) {
    Map<String, String> clean = new LinkedHashMap<>();
    if (detail == null) {
      return clean;
    }
    for (Map.Entry<String, String> entry : detail.entrySet()) {
      String key = entry.getKey();
      if (key == null || SENSITIVE_KEY.matcher(key).matches()) {
        continue;
      }
      clean.put(key, truncate(entry.getValue()));
    }
    return clean;
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
      if (key == null || SENSITIVE_KEY.matcher(key).matches()) {
        continue;
      }
      Object value = entry.getValue();
      if (value == null) {
        clean.put(key, "");
      } else if (value instanceof String text) {
        clean.put(key, truncate(text));
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

  private static String truncate(String value) {
    if (value == null) {
      return "";
    }
    return value.length() > MAX_VALUE_CHARS ? value.substring(0, MAX_VALUE_CHARS) : value;
  }
}
