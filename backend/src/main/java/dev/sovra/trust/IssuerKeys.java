package dev.sovra.trust;

import java.time.Instant;
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Live issuer-key authorization (SOV-012). A key signs, issues, or
 * verifies only when the registry names it ACTIVE at the exact
 * referenced version and no revocation row terminally retires it.
 * Every caller checks live — never from a warmed positive cache —
 * so a compromise takes effect on the next operation.
 */
public final class IssuerKeys {

  private IssuerKeys() {}

  public static boolean active(
      JdbcTemplate jdbc, String issuerId, String keyId, int keyVersion) {
    List<String> rows =
        jdbc.query(
            "SELECT status FROM issuer_signing_key"
                + " WHERE issuer_id = ? AND key_id = ? AND key_version = ?",
            (rs, row) -> rs.getString(1),
            issuerId, keyId, keyVersion);
    if (rows.size() != 1 || !"ACTIVE".equals(rows.get(0))) {
      return false;
    }
    Integer revoked =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM issuer_key_revocation"
                + " WHERE issuer_id = ? AND key_id = ? AND key_version = ?",
            Integer.class,
            issuerId, keyId, keyVersion);
    return revoked == null || revoked == 0;
  }

  /**
   * Registry usability (SOV-009, SOV-014): ACTIVE standing inside the
   * validity window. Null bounds fail closed. The single predicate
   * every verifier, issuer, guard, and planner shares, so discovery
   * can never surface an issuer the verifier would refuse.
   */
  public static boolean usable(TrustService.IssuerView issuer, Instant now) {
    return "ACTIVE".equals(issuer.status())
        && issuer.validFrom() != null
        && issuer.validThrough() != null
        && !issuer.validFrom().isAfter(now)
        && !issuer.validThrough().isBefore(now);
  }
}
