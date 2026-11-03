package dev.sovra.planning;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.guard.GuardPolicies;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Prompt freeze for governed discovery: the template names no fixture
 * schemas, so a novel compatible mapping can only come from tool outputs,
 * never from a prompt hint. Unscoped prompts render byte-identically to
 * the pre-scope shape; scoped prompts add one generic section echoing
 * caller data as data. Pure unit tests.
 */
class PromptFreezeTests {

  static final List<String> FIXTURE_NAMES = List.of(
      "fjord", "Fjord", "FJORD",
      "isAdult",
      "harbor", "Harbor", "HARBOR",
      "qualifiesAsAdult",
      "employment", "Employment", "EMPLOYMENT",
      "yearsInEmployment",
      "synth-2", "synth2");

  private static PlanningIntent unscoped() {
    return PlanningIntents.validate(
        "https://rp.example/synth-shop",
        "https://rp.example/synth-shop/callback",
        "synthetic age check",
        "age_over_18",
        GuardPolicies.MAPPED_POLICY_ID,
        GuardPolicies.MAPPED_POLICY_VERSION,
        List.of("adultOver18"));
  }

  @Test
  void systemPromptNamesNoFixture() {
    String system = PlanningPrompts.system();
    for (String name : FIXTURE_NAMES) {
      assertThat(system).as("system prompt must not name %s", name).doesNotContain(name);
    }
  }

  @Test
  void unscopedUserPromptNamesNoFixtureAndCarriesNoScopeSection() {
    String user = PlanningPrompts.user(unscoped());
    for (String name : FIXTURE_NAMES) {
      assertThat(user).as("user prompt must not name %s", name).doesNotContain(name);
    }
    assertThat(user).doesNotContain("Discovery scope");
    assertThat(user)
        .contains("age_over_18")
        .contains(GuardPolicies.MAPPED_POLICY_ID)
        .contains("adultOver18");
  }

  @Test
  void scopedUserPromptEchoesCallerDataWithoutFixtureGuidance() {
    PlanningIntent scoped = PlanningIntents.validate(
        "https://rp.example/synth-shop",
        "https://rp.example/synth-shop/callback",
        "synthetic age check",
        "age_over_18",
        GuardPolicies.MAPPED_POLICY_ID,
        GuardPolicies.MAPPED_POLICY_VERSION,
        List.of("adultOver18"),
        List.of("https://example.test/issuers/neutral-9"),
        List.of("https://example.test/vct/neutral/1"),
        List.of("neutral-hint"));
    String user = PlanningPrompts.user(scoped);
    // Caller data echoes as data.
    assertThat(user)
        .contains("neutral-9")
        .contains("Discovery scope");
    // But the template still guides nothing fixture-specific.
    for (String name : FIXTURE_NAMES) {
      assertThat(user).as("scoped prompt must not name %s", name).doesNotContain(name);
    }
  }

  @Test
  void promptVersionIsThree() {
    assertThat(PlanningVersions.PROMPT_VERSION).isEqualTo("sovra-planner-prompts/3");
  }
}
