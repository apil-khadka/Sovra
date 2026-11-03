package dev.sovra.config;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.planning.AiBudgetProperties;
import dev.sovra.planning.PlanningProperties;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * Root-compose AI wiring (PROD-012 review fix): the nine
 * bound/timeout/tool/output variables plus the arming/credential
 * and budget variables must reach both app replicas with safe
 * defaults, and explicit values must bind through Spring relaxed
 * binding. Asserts on keys and defaults only — never reads the
 * real {@code .env} and never prints secret values.
 */
class AiComposeMappingTests {

  static final Path ROOT_COMPOSE = Path.of("../compose.yaml");
  static final Path ENV_EXAMPLE = Path.of("../.env.example");

  @Test
  void rootComposeForwardsAiBoundsToBothReplicas() throws Exception {
    assertThat(ROOT_COMPOSE).exists();
    String yaml = Files.readString(ROOT_COMPOSE);
    for (String service : new String[] {"app-a", "app-b"}) {
      String block = appBlock(yaml, service);
      // Arming/credential (pre-existing).
      assertThat(block).contains("SOVRA_AI_LIVE_ENABLED: ${SOVRA_AI_LIVE_ENABLED:-false}");
      assertThat(block).contains("SOVRA_AI_BASE_URL: ${SOVRA_AI_BASE_URL:-}");
      assertThat(block).contains("SOVRA_AI_MODEL: ${SOVRA_AI_MODEL:-}");
      assertThat(block).contains("SOVRA_AI_API_KEY: ${SOVRA_AI_API_KEY:-}");
      // Bounds (review fix): empty allowlist denies, retries 0,
      // transcript 32768, rest match PlanningProperties defaults.
      assertThat(block).contains("SOVRA_AI_ALLOWED_MODELS: ${SOVRA_AI_ALLOWED_MODELS:-}");
      assertThat(block).contains("SOVRA_AI_MAX_RETRIES: ${SOVRA_AI_MAX_RETRIES:-0}");
      assertThat(block)
          .contains("SOVRA_AI_MAX_TRANSCRIPT_BYTES: ${SOVRA_AI_MAX_TRANSCRIPT_BYTES:-32768}");
      assertThat(block).contains("SOVRA_AI_MAX_TOOL_CALLS: ${SOVRA_AI_MAX_TOOL_CALLS:-8}");
      assertThat(block).contains("SOVRA_AI_TIMEOUT: ${SOVRA_AI_TIMEOUT:-10s}");
      assertThat(block).contains("SOVRA_AI_MAX_TOKENS: ${SOVRA_AI_MAX_TOKENS:-8000}");
      assertThat(block)
          .contains("SOVRA_AI_MAX_PROMPT_CHARS: ${SOVRA_AI_MAX_PROMPT_CHARS:-8000}");
      assertThat(block).contains("SOVRA_AI_TEMPERATURE: ${SOVRA_AI_TEMPERATURE:-0.0}");
      assertThat(block).contains("SOVRA_AI_SEED: ${SOVRA_AI_SEED:-7}");
      // Budgets (pre-existing).
      assertThat(block)
          .contains("SOVRA_AI_BUDGET_DAILY_REQUESTS: ${SOVRA_AI_BUDGET_DAILY_REQUESTS:-0}");
      assertThat(block)
          .contains("SOVRA_AI_BUDGET_DAILY_TOKENS: ${SOVRA_AI_BUDGET_DAILY_TOKENS:-0}");
      assertThat(block)
          .contains("SOVRA_AI_BUDGET_MAX_CONCURRENCY: ${SOVRA_AI_BUDGET_MAX_CONCURRENCY:-0}");
      assertThat(block)
          .contains("SOVRA_AI_BUDGET_LEASE_SECONDS: ${SOVRA_AI_BUDGET_LEASE_SECONDS:-120}");
    }
    // Compose defaults match the code defaults (deny-by-default).
    PlanningProperties code = new PlanningProperties();
    assertThat(code.liveEnabled()).isFalse();
    assertThat(code.allowedModels()).isEmpty();
    assertThat(code.maxRetries()).isZero();
    assertThat(code.maxTranscriptBytes()).isEqualTo(32768);
    assertThat(code.maxToolCalls()).isEqualTo(8);
    assertThat(code.timeout()).isEqualTo(Duration.ofSeconds(10));
    assertThat(code.maxTokens()).isEqualTo(8000);
    assertThat(code.maxPromptChars()).isEqualTo(8000);
    assertThat(code.temperature()).isZero();
    assertThat(code.seed()).isEqualTo(7);
    AiBudgetProperties budgets = new AiBudgetProperties();
    assertThat(budgets.dailyRequests()).isZero();
    assertThat(budgets.dailyTokens()).isZero();
    assertThat(budgets.maxConcurrency()).isZero();
    assertThat(budgets.leaseSeconds()).isEqualTo(120);
    // Never auto-allow: no model id is hardcoded into the allowlist.
    assertThat(yaml).doesNotContain("SOVRA_AI_ALLOWED_MODELS: meta-");
    assertThat(yaml).doesNotContain("SOVRA_AI_ALLOWED_MODELS: ${SOVRA_AI_MODEL");
  }

  @Test
  void envExampleDocumentsAiBoundsWithSafeDefaults() throws Exception {
    assertThat(ENV_EXAMPLE).exists();
    String env = Files.readString(ENV_EXAMPLE);
    assertThat(env).contains("SOVRA_AI_LIVE_ENABLED=false");
    // Empty credential placeholder — no secret is committed here.
    assertThat(env).contains("SOVRA_AI_API_KEY=\n");
    assertThat(env).contains("SOVRA_AI_ALLOWED_MODELS=\n");
    assertThat(env).contains("SOVRA_AI_MAX_RETRIES=0");
    assertThat(env).contains("SOVRA_AI_MAX_TRANSCRIPT_BYTES=32768");
    assertThat(env).contains("SOVRA_AI_MAX_TOOL_CALLS=8");
    assertThat(env).contains("SOVRA_AI_TIMEOUT=10s");
    assertThat(env).contains("SOVRA_AI_MAX_TOKENS=8000");
    assertThat(env).contains("SOVRA_AI_MAX_PROMPT_CHARS=8000");
    assertThat(env).contains("SOVRA_AI_TEMPERATURE=0.0");
    assertThat(env).contains("SOVRA_AI_SEED=7");
  }

  @Test
  void explicitAiBoundsBind() {
    // Property names mirror the SOVRA_AI_* env vars through Spring
    // relaxed binding; proving the properties bind proves an
    // explicitly set container env binds the same way.
    new ApplicationContextRunner()
        .withUserConfiguration(BoundConfig.class)
        .withPropertyValues(
            "sovra.ai.allowed-models=m1,m2",
            "sovra.ai.max-retries=0",
            "sovra.ai.max-transcript-bytes=12345",
            "sovra.ai.max-tool-calls=5",
            "sovra.ai.timeout=15s",
            "sovra.ai.max-tokens=4000",
            "sovra.ai.max-prompt-chars=4000",
            "sovra.ai.temperature=0.5",
            "sovra.ai.seed=42")
        .run(
            ctx -> {
              PlanningProperties props = ctx.getBean(PlanningProperties.class);
              assertThat(props.allowedModels()).containsExactly("m1", "m2");
              assertThat(props.maxRetries()).isZero();
              assertThat(props.maxTranscriptBytes()).isEqualTo(12345);
              assertThat(props.maxToolCalls()).isEqualTo(5);
              assertThat(props.timeout()).isEqualTo(Duration.ofSeconds(15));
              assertThat(props.maxTokens()).isEqualTo(4000);
              assertThat(props.maxPromptChars()).isEqualTo(4000);
              assertThat(props.temperature()).isEqualTo(0.5);
              assertThat(props.seed()).isEqualTo(42);
            });
  }

  @Test
  void emptyAllowlistDenies() {
    // The compose empty default binds to empty-or-blank, which never
    // qualifies any model id — the LivePlanner gate denies.
    new ApplicationContextRunner()
        .withUserConfiguration(BoundConfig.class)
        .withPropertyValues("sovra.ai.allowed-models=")
        .run(
            ctx -> {
              PlanningProperties props = ctx.getBean(PlanningProperties.class);
              assertThat(
                      props.allowedModels().stream().filter(s -> !s.isBlank()).toList())
                  .isEmpty();
              assertThat(props.allowedModels()).doesNotContain("fake-model");
            });
    new ApplicationContextRunner()
        .withUserConfiguration(BoundConfig.class)
        .run(
            ctx ->
                assertThat(ctx.getBean(PlanningProperties.class).allowedModels())
                    .isEmpty());
  }

  @EnableConfigurationProperties(PlanningProperties.class)
  static class BoundConfig {}

  private static String appBlock(String yaml, String service) {
    int start = yaml.indexOf("\n  " + service + ":");
    assertThat(start).isGreaterThanOrEqualTo(0);
    Matcher next = Pattern.compile("\n  \\S").matcher(yaml);
    int end = yaml.length();
    while (next.find()) {
      if (next.start() > start) {
        end = next.start();
        break;
      }
    }
    return yaml.substring(start, end);
  }
}
