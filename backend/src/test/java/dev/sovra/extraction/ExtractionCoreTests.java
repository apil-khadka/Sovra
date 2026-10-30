package dev.sovra.extraction;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Pure extraction core (SOV-018): fixture parsing, normalizer-v1,
 * and the canonical/exact digest split. No Spring, no database.
 */
class ExtractionCoreTests {

  private final SyntheticFixtureEngine engine = new SyntheticFixtureEngine();

  @Test
  void fixtureParsesKnownFields() {
    ExtractionOutcome outcome = engine.run(fixtureBytes(
        "SOVRA-FIXTURE/v1\n"
            + "name: Ana Example\n"
            + "document_number: X1234567\n"
            + "date_of_birth: 1990-01-02\n"
            + "country: NL\n"), SyntheticFixtureEngine.SCHEMA_ID);
    assertThat(outcome.observed()).containsExactlyInAnyOrderEntriesOf(Map.of(
        "name", "Ana Example",
        "document_number", "X1234567",
        "date_of_birth", "1990-01-02",
        "country", "NL"));
    assertThat(outcome.confidence()).isEqualTo(1.0);
  }

  @Test
  void wrongSourceTerminates() {
    String[] bad = {
      "not a fixture\nname: Ana\n",
      "SOVRA-FIXTURE/v1\nname: Ana\n",
      "SOVRA-FIXTURE/v1\nname: Ana\ndocument_number: X1\ndate_of_birth: 1990-01-02\n"
          + "unknown_field: nope\n",
      "SOVRA-FIXTURE/v1\nname: Ana\nname: Bob\ndocument_number: X1\n"
          + "date_of_birth: 1990-01-02\n",
      "SOVRA-FIXTURE/v1\nname: Ana\ndocument_number: X1\ndate_of_birth: 1990-01-02\nno-colon\n",
      ""
    };
    for (String source : bad) {
      assertThatThrownBy(() -> engine.run(
          source.getBytes(StandardCharsets.UTF_8), SyntheticFixtureEngine.SCHEMA_ID))
          .isInstanceOf(ExtractionInvalidException.class);
    }
    assertThatThrownBy(() -> engine.run(new byte[] {(byte) 0xFF, (byte) 0xFE},
        SyntheticFixtureEngine.SCHEMA_ID))
        .isInstanceOf(ExtractionInvalidException.class);
    assertThatThrownBy(() -> engine.run(fixtureBytes(
        "SOVRA-FIXTURE/v1\nname: Ana\ndocument_number: X1\ndate_of_birth: 1990-01-02\n"),
        "other-schema"))
        .isInstanceOf(ExtractionInvalidException.class);
  }

  @Test
  void normalizerTrimsCollapsesAndFoldsOnlyNames() {
    assertThat(FieldNormalizer.normalize("name", "  Ana   Example  ")).isEqualTo("ana example");
    assertThat(FieldNormalizer.normalize("country", "NL")).isEqualTo("nl");
    assertThat(FieldNormalizer.normalize("document_number", "  X123 4567 "))
        .isEqualTo("X123 4567");
    assertThat(FieldNormalizer.normalize("date_of_birth", "1990-01-02")).isEqualTo("1990-01-02");
    // e + combining acute normalizes to the precomposed form.
    assertThat(FieldNormalizer.normalize("name", "Jose\u0301"))
        .isEqualTo(FieldNormalizer.normalize("name", "Jos\u00E9"));
  }

  @Test
  void canonicalDigestIgnoresCaseWhileExactDoesNot() {
    String a = FieldNormalizer.normalize("name", "Ana Example");
    String b = FieldNormalizer.normalize("name", "ana example");
    assertThat(FieldDigests.canonical(a)).isEqualTo(FieldDigests.canonical(b));
    assertThat(FieldDigests.exact("Ana Example")).isNotEqualTo(FieldDigests.exact("ana example"));
  }

  @Test
  void digestsAreSha256HexStable() {
    byte[] digest = FieldDigests.canonical("ana example");
    assertThat(digest).hasSize(32);
    assertThat(HexFormat.of().formatHex(digest))
        .isEqualTo(HexFormat.of().formatHex(FieldDigests.canonical("ana example")));
  }

  private static byte[] fixtureBytes(String text) {
    return text.getBytes(StandardCharsets.UTF_8);
  }
}
