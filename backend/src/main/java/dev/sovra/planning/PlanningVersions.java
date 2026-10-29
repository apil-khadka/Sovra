package dev.sovra.planning;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import org.springframework.ai.tool.ToolCallback;

/**
 * Frozen planning versions (SOV-013, FR-11, NFR-10). The prompt text,
 * the tool contract, and the baseline engine carry versions recorded
 * with every proposal and evaluation run, so comparisons reproduce.
 * Changing any frozen string requires a version bump here plus the
 * refreshed tool-schema hash.
 */
public final class PlanningVersions {

  /** System/user prompt template version; text lives in PlanningPrompts. */
  public static final String PROMPT_VERSION = "sovra-planner-prompts/2";

  /** Tool name/description/schema contract version. */
  public static final String TOOL_CONTRACT_VERSION = "sovra-planner-tools/1";

  /** Deterministic comparison engine version (no model involved). */
  public static final String BASELINE_VERSION = "sovra-baseline-planner/1";

  /** Synthetic planning result profile label. */
  public static final String PROFILE = "sovra-synthetic-planning/1";

  private PlanningVersions() {}

  /**
   * Stable SHA-256 over the live tool definitions (name, description,
   * input schema, sorted by name). Recorded with every run; the
   * committed tests pin the expected value, so any tool-contract drift
   * fails loudly instead of silently changing comparisons.
   */
  public static String toolSchemaHash(List<ToolCallback> callbacks) {
    StringBuilder canonical = new StringBuilder();
    callbacks.stream()
        .map(c -> c.getToolDefinition().name()
            + "\n" + c.getToolDefinition().description()
            + "\n" + c.getToolDefinition().inputSchema())
        .sorted()
        .forEach(part -> canonical.append(part).append("\n"));
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256")
          .digest(canonical.toString().getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is mandatory", e);
    }
  }
}
