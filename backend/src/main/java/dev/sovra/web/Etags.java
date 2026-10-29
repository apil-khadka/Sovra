package dev.sovra.web;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * Strong ETags over stable view bytes (SOV-015, IF-11). The tag changes
 * whenever the represented view changes, so a matching
 * {@code If-None-Match} proves the caller already holds the current
 * representation. Tags are content hashes, never database ids.
 */
public final class Etags {

  private Etags() {}

  /** Strong ETag for a canonical view rendering, including quotes. */
  public static String strong(String canonical) {
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8));
      return "\"" + HexFormat.of().formatHex(digest) + "\"";
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is mandatory", e);
    }
  }

  /** Exact-match precondition only; {@code *} never matches (see compat doc). */
  public static boolean matches(String etag, String ifNoneMatch) {
    return ifNoneMatch != null && etag.equals(ifNoneMatch.trim());
  }

  /**
   * 304 when the caller holds the current representation, else 200
   * with the tag. Keeps every conditional-GET site identical.
   */
  public static <T> ResponseEntity<T> respond(T view, String ifNoneMatch) {
    String etag = strong(view.toString());
    if (matches(etag, ifNoneMatch)) {
      return ResponseEntity.status(HttpStatus.NOT_MODIFIED).eTag(etag).build();
    }
    return ResponseEntity.ok().eTag(etag).body(view);
  }
}
