package dev.sovra.retention;

import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Nightly audit archival (PROD-010). Evidence older than 90 days
 * moves to the archive table in one bounded batch per night;
 * held tenants' rows stay hot until the hold releases. Reads
 * union both tables, so archival is a storage optimization, never
 * a visibility change. Every replica may run it — the function
 * locks skipped rows and never moves one twice.
 */
@Component
public class AuditArchive {

  static final int BATCH = 1_000;

  private static final Logger log = LoggerFactory.getLogger(AuditArchive.class);

  private final JdbcTemplate global;

  public AuditArchive(DataSource globalDataSource) {
    this.global = new JdbcTemplate(globalDataSource);
  }

  @Scheduled(cron = "0 45 3 * * *")
  public void archive() {
    Integer moved =
        global.queryForObject("SELECT archive_audit_events(?)", Integer.class, BATCH);
    if (moved != null && moved > 0) {
      log.info("archived {} audit events", moved);
    }
  }
}
