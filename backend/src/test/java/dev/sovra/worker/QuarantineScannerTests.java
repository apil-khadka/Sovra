package dev.sovra.worker;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStream;
import org.junit.jupiter.api.Test;

/**
 * Hostile-image scanner verdicts (SOV-017): allowlisted decodes pass
 * with dimensions, and every hostile shape — spoofed magic, appended
 * polyglot payloads, header bombs, truncation, corrupt scan data —
 * names its rejection reason without throwing content.
 */
class QuarantineScannerTests {

  private static byte[] fixture(String name) throws Exception {
    try (InputStream in =
        QuarantineScannerTests.class.getResourceAsStream("/quarantine/" + name)) {
      assertThat(in).as("fixture " + name).isNotNull();
      return in.readAllBytes();
    }
  }

  @Test
  void validPngIsCleanWithDimensions() throws Exception {
    QuarantineScanner.Verdict verdict = QuarantineScanner.scan(fixture("tiny.png"));
    assertThat(verdict.clean()).isTrue();
    assertThat(verdict.reason()).isEqualTo("clean");
    assertThat(verdict.width()).isEqualTo(8);
    assertThat(verdict.height()).isEqualTo(8);
  }

  @Test
  void validJpegIsCleanWithDimensions() throws Exception {
    QuarantineScanner.Verdict verdict = QuarantineScanner.scan(fixture("tiny.jpg"));
    assertThat(verdict.clean()).isTrue();
    assertThat(verdict.reason()).isEqualTo("clean");
    assertThat(verdict.width()).isEqualTo(8);
    assertThat(verdict.height()).isEqualTo(8);
  }

  @Test
  void spoofedMagicIsRejected() throws Exception {
    QuarantineScanner.Verdict verdict = QuarantineScanner.scan(fixture("spoof.gif"));
    assertThat(verdict.clean()).isFalse();
    assertThat(verdict.reason()).isEqualTo("unknown-type");
  }

  @Test
  void pngPolyglotIsRejected() throws Exception {
    QuarantineScanner.Verdict verdict = QuarantineScanner.scan(fixture("polyglot.png"));
    assertThat(verdict.clean()).isFalse();
    assertThat(verdict.reason()).isEqualTo("trailing-data");
  }

  @Test
  void jpegPolyglotIsRejected() throws Exception {
    QuarantineScanner.Verdict verdict = QuarantineScanner.scan(fixture("polyglot.jpg"));
    assertThat(verdict.clean()).isFalse();
    assertThat(verdict.reason()).isEqualTo("trailing-data");
  }

  @Test
  void dimensionBombDiesOnTheHeader() throws Exception {
    QuarantineScanner.Verdict verdict = QuarantineScanner.scan(fixture("bomb.png"));
    assertThat(verdict.clean()).isFalse();
    assertThat(verdict.reason()).isEqualTo("dimension-cap");
  }

  @Test
  void truncatedPngIsRejected() throws Exception {
    QuarantineScanner.Verdict verdict = QuarantineScanner.scan(fixture("truncated.png"));
    assertThat(verdict.clean()).isFalse();
    assertThat(verdict.reason()).isEqualTo("truncated");
  }

  @Test
  void corruptJpegIsRejected() throws Exception {
    QuarantineScanner.Verdict verdict = QuarantineScanner.scan(fixture("corrupt.jpg"));
    assertThat(verdict.clean()).isFalse();
    assertThat(verdict.reason()).isEqualTo("malformed");
  }

  @Test
  void corruptScanDataIsRejected() throws Exception {
    QuarantineScanner.Verdict verdict = QuarantineScanner.scan(fixture("corrupt-idat.png"));
    assertThat(verdict.clean()).isFalse();
    assertThat(verdict.reason()).isEqualTo("decode-failed");
  }

  @Test
  void emptyInputIsRejected() {
    assertThat(QuarantineScanner.scan(new byte[0]).reason()).isEqualTo("empty");
    assertThat(QuarantineScanner.scan(null).reason()).isEqualTo("empty");
  }
}
