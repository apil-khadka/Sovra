package dev.sovra;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.MapPropertySource;

/**
 * Full-boot production refusal (SOV-040): the same synthetic database
 * that serves demo traffic refuses a production boot — including the
 * post-restore shape, where the data predates the production attempt.
 * No Spring test context here; each boot is explicit and closed.
 */
class ProductionBootTests extends SovraPostgresBase {

  private static Map<String, Object> datasourceProperties() {
    Map<String, Object> props = new HashMap<>();
    props.put("spring.datasource.url", POSTGRES.getJdbcUrl());
    props.put("spring.datasource.username", POSTGRES.getUsername());
    props.put("spring.datasource.password", POSTGRES.getPassword());
    props.put("spring.flyway.user", POSTGRES.getUsername());
    props.put("spring.flyway.password", POSTGRES.getPassword());
    props.put("server.port", "0");
    return props;
  }

  private static ConfigurableApplicationContext boot(Map<String, Object> extra) {
    Map<String, Object> props = datasourceProperties();
    props.putAll(extra);
    // Builder properties are lowest-precedence defaults and lose to
    // application.yaml; the test database must win, so prepend it.
    return new SpringApplicationBuilder(SovraApplication.class)
        .initializers(
            ctx -> ctx.getEnvironment().getPropertySources()
                .addFirst(new MapPropertySource("production-boot-test", props)))
        .run();
  }

  @Test
  void syntheticDatabaseServesDemoButRefusesProduction() {
    try (ConfigurableApplicationContext demoBoot = boot(Map.of(
        "sovra.mode", "demo",
        "sovra.signer", "local-dev",
        "sovra.profile", "synthetic"))) {
      assertThat(demoBoot.containsBean("trustService")).isTrue();
    }
    assertThatThrownBy(() -> boot(Map.of(
            "sovra.mode", "production",
            "sovra.signer", "kms",
            "sovra.profile", "sdjwt-vc")))
        .hasStackTraceContaining("production entry refused");
  }
}
