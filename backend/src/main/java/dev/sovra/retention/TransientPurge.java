package dev.sovra.retention;

import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Nightly transient-record reaping (PROD-010). Each purge is a
 * bounded SECURITY DEFINER call (see V34): at most 1,000 rows per
 * table per night in expiry order, so a backlog drains over
 * successive nights instead of one long lock. Every replica may
 * run it — the functions are idempotent and the overlap only
 * reaps nothing twice.
 */
@Component
public class TransientPurge {

  static final int BATCH = 1_000;

  private static final Logger log = LoggerFactory.getLogger(TransientPurge.class);

  private final JdbcTemplate global;

  public TransientPurge(DataSource globalDataSource) {
    this.global = new JdbcTemplate(globalDataSource);
  }

  @Scheduled(cron = "0 30 3 * * *")
  public void purge() {
    purge("vault grants", "SELECT purge_expired_vault_grants(?)");
    purge("issuance idempotency mappings", "SELECT purge_expired_issuance_idempotency(?)");
    // Tokens before grants: vci_token references vci_grant, so
    // parent-first order would violate the foreign key.
    purge("VCI tokens", "SELECT purge_expired_vci_tokens(?)");
    purge("VCI grants", "SELECT purge_expired_vci_grants(?)");
    purge("VP sessions", "SELECT purge_expired_vp_sessions(?)");
  }

  private void purge(String label, String sql) {
    Integer removed = global.queryForObject(sql, Integer.class, BATCH);
    if (removed != null && removed > 0) {
      log.info("reaped {} expired {}", removed, label);
    }
  }
}
