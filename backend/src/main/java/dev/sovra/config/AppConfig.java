package dev.sovra.config;

import dev.sovra.authz.PermissionCache;
import dev.sovra.tenancy.TenantDataSource;
import java.time.Clock;
import javax.sql.DataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Application beans. Exactly one {@link DataSource} bean exists so Boot's
 * Flyway, transaction, and health auto-configuration stays intact; the
 * tenant-scoped template wraps it without registering a second datasource.
 *
 * <p>Scheduling is enabled for infrastructure reaping only: Spring
 * Session's expired-session cleanup and the unlock-challenge purge.
 * Both are idempotent across replicas.
 */
@Configuration
@EnableScheduling
public class AppConfig {

  @Bean
  Clock clock() {
    return Clock.systemUTC();
  }

  @Bean
  PermissionCache permissionCache(Clock clock) {
    return new PermissionCache(clock);
  }

  @Bean
  JdbcTemplate tenantJdbcTemplate(DataSource dataSource) {
    return new JdbcTemplate(new TenantDataSource(dataSource));
  }
}
