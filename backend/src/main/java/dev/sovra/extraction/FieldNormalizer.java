package dev.sovra.extraction;

import java.text.Normalizer;
import java.util.Locale;
import java.util.Set;

/**
 * Field normalization {@code normalizer-v1} (OD-15, DR-14): NFC,
 * Unicode-aware trim, interior whitespace collapse, then
 * case-folding for {@code name} and {@code country} only. Document
 * numbers and dates keep case so normalization can never merge
 * distinct identifiers.
 */
public final class FieldNormalizer {

  public static final String NORMALIZER_ID = "normalizer-v1";

  private static final Set<String> CASE_FOLDED = Set.of("name", "country");

  private FieldNormalizer() {}

  public static String normalize(String field, String observed) {
    if (field == null || observed == null) {
      throw new ExtractionInvalidException("field and value are required");
    }
    String value = Normalizer.normalize(observed, Normalizer.Form.NFC).strip();
    value = value.replaceAll("\\p{IsWhite_Space}+", " ");
    if (CASE_FOLDED.contains(field)) {
      value = value.toLowerCase(Locale.ROOT);
    }
    return value;
  }
}
