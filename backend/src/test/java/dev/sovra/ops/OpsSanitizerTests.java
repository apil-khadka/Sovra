package dev.sovra.ops;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Output sanitizer for operations surfaces: secret-like keys never pass. */
class OpsSanitizerTests {

  @Test
  void detailDropsSecretLikeKeysAndTruncatesLongValues() {
    Map<String, String> detail = new LinkedHashMap<>();
    detail.put("note", "ok");
    detail.put("api_key", "should-vanish");
    detail.put("holder_proof_jws", "should-vanish");
    detail.put("long", "x".repeat(600));

    Map<String, String> clean = OpsSanitizer.sanitizeDetail(detail);

    assertThat(clean).containsOnlyKeys("note", "long");
    assertThat(clean.get("note")).isEqualTo("ok");
    assertThat(clean.get("long")).hasSize(OpsSanitizer.MAX_VALUE_CHARS);
  }

  @Test
  void detailIsNullSafeAndCaseInsensitive() {
    assertThat(OpsSanitizer.sanitizeDetail(null)).isEmpty();
    assertThat(OpsSanitizer.sanitizeDetail(Map.of("TOKEN", "v"))).isEmpty();
    assertThat(OpsSanitizer.sanitizeDetail(Map.of("Password", "v"))).isEmpty();
  }

  @Test
  void objectsPassScalarsAndRedactForeignTypes() {
    Map<String, Object> detail = new LinkedHashMap<>();
    detail.put("count", 3L);
    detail.put("ready", Boolean.TRUE);
    detail.put("at", Instant.parse("2026-01-01T00:00:00Z"));
    detail.put("status", CheckStatus.UP);
    detail.put("secret", "drop-me");
    detail.put("blob", new byte[] {1, 2, 3});

    Map<String, Object> clean = OpsSanitizer.sanitizeObjects(detail);

    assertThat(clean.get("count")).isEqualTo(3L);
    assertThat(clean.get("ready")).isEqualTo(Boolean.TRUE);
    assertThat(clean.get("status")).isEqualTo(CheckStatus.UP);
    assertThat(clean).doesNotContainKey("secret");
    assertThat(clean.get("blob")).isEqualTo("redacted:byte[]");
  }

  @Test
  void objectsTruncateLongStrings() {
    Map<String, Object> clean =
        OpsSanitizer.sanitizeObjects(Map.of("text", "y".repeat(1000)));
    assertThat((String) clean.get("text")).hasSize(OpsSanitizer.MAX_VALUE_CHARS);
  }
}
