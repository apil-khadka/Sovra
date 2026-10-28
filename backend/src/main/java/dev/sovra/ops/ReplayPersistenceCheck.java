package dev.sovra.ops;

import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;
import org.springframework.stereotype.Component;

/**
 * Replay-persistence dependency: verification replay safety rests on the
 * atomic nonce-consumption INSERT. Proves the write path with a
 * rollback-only probe carrying valid-shaped values (only the tenant and
 * referenced rows are fictitious); persists nothing.
 */
@Component
public class ReplayPersistenceCheck implements ReadinessCheck {

  private final DataSource dataSource;

  public ReplayPersistenceCheck(DataSource globalDataSource) {
    this.dataSource = globalDataSource;
  }

  @Override
  public String name() {
    return "replay_persistence";
  }

  @Override
  public CheckResult check() {
    return RollbackProbe.probe(
        name(),
        dataSource,
        "INSERT INTO verification_decision (tenant_id, request_id, credential_id, nonce,"
            + " request_hash, rp_id, audience, outcome, reason_code, response_body,"
            + " trust_snapshot_version, decided_by)"
            + " VALUES (?, ?, ?, 'readiness-probe-000', 'probe', 'probe', 'probe', 'UNKNOWN',"
            + " 'PROBE', '{}', 0, 'readiness')",
        List.of(UUID.randomUUID(), UUID.randomUUID()));
  }
}
