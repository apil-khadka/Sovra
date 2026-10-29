package dev.sovra.web;

import java.util.Base64;
import java.util.function.Function;

/** Shared request-body decoders for the web layer. */
public final class Bodies {

  private Bodies() {}

  /**
   * Base64 request bytes, or the caller's domain exception on
   * malformed input. One message for every base64 body field.
   */
  public static byte[] base64(String raw, Function<String, RuntimeException> invalid) {
    try {
      return Base64.getDecoder().decode(raw);
    } catch (IllegalArgumentException e) {
      throw invalid.apply("content is not base64");
    }
  }
}
