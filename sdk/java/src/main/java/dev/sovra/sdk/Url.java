package dev.sovra.sdk;

/** Query-string encoding for SDK-built paths. */
final class Url {

  private Url() {}

  static String encode(String raw) {
    try {
      return java.net.URLEncoder.encode(raw, java.nio.charset.StandardCharsets.UTF_8);
    } catch (Exception e) {
      throw new IllegalArgumentException("value is not encodable");
    }
  }
}
