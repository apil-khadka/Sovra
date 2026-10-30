package dev.sovra.extraction;

import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Deterministic synthetic fixture engine ({@code fixture-v1},
 * OD-15). Parses {@code SOVRA-FIXTURE/v1} text documents of the
 * form {@code KEY: value} lines. Anything else terminates the run:
 * non-UTF-8 bytes, a wrong header, no recognized fields, or an
 * unknown schema. The engine performs no fuzzy parsing and emits
 * no confidence below 1 — the fixture is either exact or rejected.
 */
@Component
public class SyntheticFixtureEngine implements ExtractionEngine {

  public static final String ENGINE_ID = "fixture-v1";
  public static final String SCHEMA_ID = "fixture-doc-v1";

  private static final String HEADER = "SOVRA-FIXTURE/v1";

  private static final Set<String> REQUIRED_FIELDS =
      Set.of("name", "document_number", "date_of_birth");

  private static final Set<String> KNOWN_FIELDS =
      Set.of("name", "document_number", "date_of_birth", "expiry_date", "country");

  @Override
  public String engineId() {
    return ENGINE_ID;
  }

  @Override
  public ExtractionOutcome run(byte[] source, String schemaId) {
    if (!SCHEMA_ID.equals(schemaId)) {
      throw new ExtractionInvalidException("unknown extraction schema");
    }
    String text = decode(source);
    String[] lines = text.split("\n", -1);
    if (lines.length == 0 || !HEADER.equals(lines[0].strip())) {
      throw new ExtractionInvalidException("source is not a sovra fixture");
    }
    Map<String, String> observed = new LinkedHashMap<>();
    for (int i = 1; i < lines.length; i++) {
      String line = lines[i];
      if (line.isBlank()) {
        continue;
      }
      int colon = line.indexOf(':');
      if (colon < 0) {
        throw new ExtractionInvalidException("source is not a sovra fixture");
      }
      String key = line.substring(0, colon).strip().toLowerCase(java.util.Locale.ROOT);
      String value = line.substring(colon + 1).strip();
      if (!KNOWN_FIELDS.contains(key) || value.isEmpty() || observed.containsKey(key)) {
        throw new ExtractionInvalidException("source is not a sovra fixture");
      }
      observed.put(key, value);
    }
    if (!observed.keySet().containsAll(REQUIRED_FIELDS)) {
      throw new ExtractionInvalidException("source is not a sovra fixture");
    }
    return new ExtractionOutcome(observed, 1.0);
  }

  private static String decode(byte[] source) {
    if (source == null || source.length == 0 || source.length > 1024 * 1024) {
      throw new ExtractionInvalidException("source is not a sovra fixture");
    }
    try {
      CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();
      return decoder.decode(java.nio.ByteBuffer.wrap(source)).toString();
    } catch (CharacterCodingException e) {
      throw new ExtractionInvalidException("source is not a sovra fixture");
    }
  }
}
