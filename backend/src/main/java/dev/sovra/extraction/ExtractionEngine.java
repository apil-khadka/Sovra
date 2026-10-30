package dev.sovra.extraction;

/**
 * Local extraction engine (SOV-018, FR-36). Engines read source
 * bytes into observed strings; the demo ships one fixture engine
 * and the service layer pins its identifier per run.
 */
public interface ExtractionEngine {

  /** Stable engine identifier recorded on every run. */
  String engineId();

  /**
   * Reads source bytes under the named schema. Wrong-source input
   * terminates with {@link ExtractionInvalidException}; engines
   * never return partial or guessed fields.
   */
  ExtractionOutcome run(byte[] source, String schemaId);
}
