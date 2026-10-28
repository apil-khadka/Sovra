package dev.sovra.issuance;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * G1 synthetic status service. Status reads go through the tenant
 * template, so row-level security turns cross-tenant and missing
 * credentials into {@link StatusEvidenceFetcher.Status#UNKNOWN} instead
 * of leaking existence. Reads are always fresh, which trivially
 * satisfies the 15-minute evidence bound; production status privacy
 * (Token Status List) is a G2 requirement.
 */
@Service
public class SyntheticStatusService implements StatusEvidenceFetcher {

  static final Duration MAX_AGE = Duration.ofMinutes(15);

  private final JdbcTemplate tenant;
  private final Clock clock;

  public SyntheticStatusService(JdbcTemplate tenantJdbcTemplate, Clock clock) {
    this.tenant = tenantJdbcTemplate;
    this.clock = clock;
  }

  @Override
  public StatusEvidence fetch(UUID credentialId) {
    List<String> rows =
        tenant.query(
            "SELECT status FROM credential_artifact WHERE id = ?",
            (rs, row) -> rs.getString(1),
            credentialId);
    if (rows.size() != 1) {
      return new StatusEvidence(Status.UNKNOWN, clock.instant(), MAX_AGE);
    }
    Status status = "REVOKED".equals(rows.get(0)) ? Status.REVOKED : Status.VALID;
    return new StatusEvidence(status, clock.instant(), MAX_AGE);
  }
}
