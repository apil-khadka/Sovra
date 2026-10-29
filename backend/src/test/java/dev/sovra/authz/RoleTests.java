package dev.sovra.authz;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * The closed role set: parsing fails fast on anything outside it,
 * and every action carries a required-roles rule.
 */
class RoleTests {

  @Test
  void fromAcceptsEveryKnownRole() {
    for (Role role : Role.values()) {
      assertThat(Role.from(role.name())).isSameAs(role);
    }
  }

  @Test
  void fromRejectsUnknownNullAndWrongCase() {
    assertThatThrownBy(() -> Role.from("PLANNER"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("PLANNER");
    assertThatThrownBy(() -> Role.from(null)).isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> Role.from("tenant_member"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void parseAllRoundTripsAndRejectsFirstUnknown() {
    assertThat(Role.parseAll(new String[] {"RP_CLIENT", "TENANT_MEMBER"}))
        .isEqualTo(Set.of(Role.RP_CLIENT, Role.TENANT_MEMBER));
    assertThatThrownBy(() -> Role.parseAll(new String[] {"TENANT_MEMBER", "TYPO"}))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("TYPO");
  }

  @Test
  void everyActionHasRequiredRoles() {
    assertThatCode(AuthorizationService::assertRulesComplete).doesNotThrowAnyException();
  }
}
