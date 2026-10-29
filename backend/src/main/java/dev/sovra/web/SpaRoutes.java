package dev.sovra.web;

import java.util.Locale;
import java.util.Set;

/**
 * Same-origin SPA boundary (SOV-041): which request paths may be
 * served as public static assets or SPA history routes. Shared by
 * the security matcher and the resource fallback so the two can
 * never drift apart — a path is public if and only if it is
 * servable.
 *
 * <p>Reserved first segments keep their own chains: {@code api}
 * (machine plus BFF session surface), {@code oauth2} and
 * {@code login} (OIDC dance), {@code error} (container dispatches),
 * and {@code actuator} (operations endpoints). Everything outside
 * them is public static content by construction: exact files when
 * they exist, {@code index.html} for extensionless SPA routes, 404
 * otherwise. Matching is case-insensitive so case variants of
 * reserved paths stay protected.
 */
public final class SpaRoutes {

  private static final Set<String> RESERVED_FIRST_SEGMENTS =
      Set.of("api", "oauth2", "login", "error", "actuator");

  private SpaRoutes() {}

  /**
   * True when a GET/HEAD request line may be served as public
   * static/SPA content. Expects the raw request URI path (leading
   * slash, no query).
   */
  public static boolean isPublicStaticPath(String requestUri) {
    if (requestUri == null || !requestUri.startsWith("/")) {
      return false;
    }
    return !isReservedFirstSegment(requestUri);
  }

  /**
   * True when a missing file at the resource path falls back to
   * {@code index.html}: the root, or an extensionless path outside
   * the reserved segments. Dotted last segments are files and never
   * fall back.
   */
  public static boolean isHistoryFallback(String resourcePath) {
    if (resourcePath == null) {
      return false;
    }
    String path = stripSlashes(resourcePath);
    if (path.isEmpty()) {
      return true;
    }
    if (isReservedFirstSegment("/" + path)) {
      return false;
    }
    String last = path.substring(path.lastIndexOf('/') + 1);
    return !last.contains(".");
  }

  private static boolean isReservedFirstSegment(String slashPath) {
    int next = slashPath.indexOf('/', 1);
    String first =
        next < 0 ? slashPath.substring(1) : slashPath.substring(1, next);
    return RESERVED_FIRST_SEGMENTS.contains(first.toLowerCase(Locale.ROOT));
  }

  private static String stripSlashes(String path) {
    int start = 0;
    int end = path.length();
    while (start < end && path.charAt(start) == '/') {
      start++;
    }
    while (end > start && path.charAt(end - 1) == '/') {
      end--;
    }
    return path.substring(start, end);
  }
}
