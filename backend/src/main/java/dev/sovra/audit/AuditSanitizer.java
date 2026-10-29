package dev.sovra.audit;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Privacy-minimization rules shared by audit storage and operations
 * output. Secret-like keys are dropped and values truncated before
 * anything reaches the database or a readiness payload. One pattern
 * and one cap: the two surfaces cannot drift.
 */
public final class AuditSanitizer {

  static final int MAX_VALUE_CHARS = 500;

  private static final Pattern SENSITIVE_KEY =
      Pattern.compile(
          ".*(password|passwd|secret|token|api[_-]?key|private[_-]?key|ssn|social[_-]?security"
              + "|dob|birth|passport|credential_|proof_|jwk|seed|mnemonic).*",
          Pattern.CASE_INSENSITIVE);

  private AuditSanitizer() {}

  /** True when the key is secret-like (or null) and must be dropped. */
  public static boolean sensitiveKey(String key) {
    return key == null || SENSITIVE_KEY.matcher(key).matches();
  }

  /** Truncates to the cap; null becomes the empty string. */
  public static String truncate(String value) {
    if (value == null) {
      return "";
    }
    return value.length() > MAX_VALUE_CHARS ? value.substring(0, MAX_VALUE_CHARS) : value;
  }

  /** Drops secret-like keys and truncates values; never throws on content. */
  public static Map<String, String> sanitize(Map<String, String> detail) {
    Map<String, String> clean = new LinkedHashMap<>();
    if (detail == null) {
      return clean;
    }
    for (Map.Entry<String, String> entry : detail.entrySet()) {
      if (sensitiveKey(entry.getKey())) {
        continue;
      }
      clean.put(entry.getKey(), truncate(entry.getValue()));
    }
    return clean;
  }
}
