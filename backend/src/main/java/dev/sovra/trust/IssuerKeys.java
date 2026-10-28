package dev.sovra.trust;

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
}
