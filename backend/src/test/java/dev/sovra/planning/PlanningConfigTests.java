package dev.sovra.planning;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.trust.IssuerKeys;
import dev.sovra.trust.IssuerStatus;
import dev.sovra.trust.TrustService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

/**
 * Planning configuration posture (SOV-013, OD-02, SEC-29): default boot
 * is keyless with live planning disarmed, no credential or endpoint
 * value lives in committed configuration, the tool contract hash is
 * pinned, and the live chat model constructs from explicit config.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class PlanningConfigTests extends SovraAppRoleBase {

  /** Pinned tool-schema hash; any tool-contract change must bump versions here. */
  static final String EXPECTED_TOOL_SCHEMA_HASH =
      "2cb3ae5f78cdea7369268faf9582e8f2ae3d1dc3ec5028ee3d047bd4b61dbff2";

  @Autowired ApplicationContext context;

  @Autowired PlanningProperties properties;

  @Autowired PlanningTools tools;

  @Autowired LivePlanner live;

  @Autowired tools.jackson.databind.ObjectMapper mapper;

  @Test
  void livePlanningIsDisarmedByDefault() {
    assertThat(properties.liveEnabled()).isFalse();
    assertThat(properties.liveReady()).isFalse();
    assertThat(properties.credentialsPresent()).isFalse();
    assertThat(properties.baseUrl()).isNull();
    assertThat(properties.apiKey()).isNull();
    assertThat(properties.model()).isNull();
    // Budgets stay finite even unconfigured.
    assertThat(properties.maxToolCalls()).isPositive();
    assertThat(properties.timeout()).isNotNull();
    assertThat(properties.maxRetries()).isNotNegative();
    assertThat(properties.maxTokens()).isPositive();
    assertThat(properties.maxPromptChars()).isPositive();
  }

  @Test
  void noSpringAiChatModelBeanExistsByDefault() {
    assertThat(context.getBeanNamesForType(org.springframework.ai.chat.model.ChatModel.class))
        .isEmpty();
  }

  @Test
  void committedConfigurationCarriesNoCredentialsOrEndpoints() throws Exception {
    for (String file : new String[] {
      "src/main/resources/application.yaml", "src/test/resources/application.yaml"}) {
      String config = Files.readString(Path.of(file));
      assertThat(config).doesNotContain("api-key", "apiKey", "base-url", "baseUrl");
      assertThat(config).doesNotContain("live-enabled");
      assertThat(config.toLowerCase()).doesNotContain("llama", "meta");
    }
  }

  @Test
  void toolSchemaHashIsPinned() {
    assertThat(PlanningVersions.toolSchemaHash(tools.callbacks()))
        .isEqualTo(EXPECTED_TOOL_SCHEMA_HASH);
  }

  @Test
  void chatModelConstructsFromExplicitConfig() {
    PlanningProperties configured = new PlanningProperties();
    configured.setBaseUrl("https://model.example/v1");
    configured.setApiKey("test-only-key");
    configured.setModel("test-only-model");
    LivePlanner explicit =
        new LivePlanner(configured, tools, java.time.Clock.systemUTC(), mapper);
    assertThat(explicit.chatModel()).isNotNull();
  }

  @Test
  void issuerUsabilityMatchesIssuerAndGuard() {
    Instant now = Instant.now();
    TrustService.IssuerView active =
        new TrustService.IssuerView(
            "i", "d", "s", java.util.List.of("t"), "k", 1, null,
            now.minusSeconds(60), now.plusSeconds(60), IssuerStatus.ACTIVE);
    assertThat(IssuerKeys.usable(active, now)).isTrue();
    TrustService.IssuerView suspended =
        new TrustService.IssuerView(
            "i", "d", "s", java.util.List.of("t"), "k", 1, null,
            now.minusSeconds(60), now.plusSeconds(60), IssuerStatus.SUSPENDED);
    assertThat(IssuerKeys.usable(suspended, now)).isFalse();
    TrustService.IssuerView expired =
        new TrustService.IssuerView(
            "i", "d", "s", java.util.List.of("t"), "k", 1, null,
            now.minusSeconds(120), now.minusSeconds(60), IssuerStatus.ACTIVE);
    assertThat(IssuerKeys.usable(expired, now)).isFalse();
    TrustService.IssuerView premature =
        new TrustService.IssuerView(
            "i", "d", "s", java.util.List.of("t"), "k", 1, null,
            now.plusSeconds(60), now.plusSeconds(120), IssuerStatus.ACTIVE);
    assertThat(IssuerKeys.usable(premature, now)).isFalse();
  }
}
