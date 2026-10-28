package dev.sovra.config;

import dev.sovra.authz.PermissionCache;
import dev.sovra.tenancy.TenantDataSource;
import java.time.Clock;
import javax.sql.DataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Application beans. Exactly one {@link DataSource} bean exists so Boot's
 * Flyway, transaction, and health auto-configuration stays intact; the
 * tenant-scoped template wraps it without registering a second datasource.
 */
@Configuration
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
