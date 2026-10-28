package dev.sovra;

import static org.assertj.core.api.Assertions.assertThat;

import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

@SpringBootTest
class SovraApplicationTests extends SovraPostgresBase {

  // Plain datasource: migration_probe is global and this probe carries no
  // tenant context (the tenant template would fail closed, by design).
  @Autowired DataSource dataSource;

  @Test
  void contextLoadsAndMigrationsRan() {
    Integer probes =
        new JdbcTemplate(dataSource)
            .queryForObject("SELECT COUNT(*) FROM migration_probe", Integer.class);
    assertThat(probes).isGreaterThanOrEqualTo(1);
  }
}
