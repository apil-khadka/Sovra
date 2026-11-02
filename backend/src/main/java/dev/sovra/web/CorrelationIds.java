package dev.sovra.web;

import java.util.UUID;
import java.util.regex.Pattern;
import org.slf4j.MDC;

/**
 * Request correlation (PROD-011). Every HTTP request gets an id:
 * the caller's {@code X-Request-Id} when it is a safe token, else a
 * fresh UUID. The id travels in the {@code X-Request-Id} response
 * header, the logging MDC ({@code requestId}), error payloads, and
 * audit rows, so one value joins access logs, errors, and evidence
 * across the fleet.
 */
public final class CorrelationIds {

  public static final String HEADER = "X-Request-Id";
  public static final String MDC_KEY = "requestId";

  private static final Pattern TOKEN = Pattern.compile("[A-Za-z0-9_.~\\-]{1,128}");

  private CorrelationIds() {}

  /** Returns the current request id, or "" outside a request. */
  public static String currentOrEmpty() {
    String current = MDC.get(MDC_KEY);
    return current == null ? "" : current;
  }

  /** Returns the current request id, or a fresh UUID outside a request. */
  public static String currentOrRandom() {
    String current = MDC.get(MDC_KEY);
    return current == null ? UUID.randomUUID().toString() : current;
  }

  static boolean valid(String candidate) {
    return candidate != null && TOKEN.matcher(candidate).matches();
  }

  static void set(String requestId) {
    MDC.put(MDC_KEY, requestId);
  }

  static void clear() {
    MDC.remove(MDC_KEY);
  }
}
