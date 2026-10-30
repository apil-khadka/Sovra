package db.migration;

import dev.sovra.crypto.HolderProofException;
import dev.sovra.crypto.HolderProofs;
import dev.sovra.crypto.P256;
import java.security.interfaces.ECPublicKey;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import tools.jackson.databind.ObjectMapper;

/**
 * SOV-024: holder-key lookup column on enrollment. Holder
 * dashboards list a proven key's cases by thumbprint; the
 * thumbprint derives from the stored P-256 JWK exactly like
 * issuance does, so no new trust root enters. Computed in Java
 * because the RFC 7638 canonical form has no SQL equivalent
 * here; new rows store it at creation time.
 */
public class V26__enrollment_holder_thumbprint extends BaseJavaMigration {

  @Override
  public void migrate(Context context) throws Exception {
    // The connection belongs to Flyway's transaction: statements
    // close, the connection itself must not.
    ObjectMapper mapper = new ObjectMapper();
    Connection connection = context.getConnection();
    try (Statement alter = connection.createStatement()) {
      alter.execute("ALTER TABLE enrollment ADD COLUMN IF NOT EXISTS holder_thumbprint TEXT");
      List<UUID> ids = new ArrayList<>();
      List<String> thumbs = new ArrayList<>();
      try (Statement select = connection.createStatement();
          ResultSet rows = select.executeQuery(
              "SELECT id, holder_jwk FROM enrollment WHERE holder_thumbprint IS NULL")) {
        while (rows.next()) {
          UUID id = rows.getObject("id", UUID.class);
          ECPublicKey key;
          try {
            key = HolderProofs.parseP256Key(mapper.readTree(rows.getString("holder_jwk")));
          } catch (HolderProofException e) {
            throw new IllegalStateException(
                "enrollment " + id + " carries an unparseable holder key", e);
          }
          ids.add(id);
          thumbs.add(P256.thumbprint(key.getW().getAffineX(), key.getW().getAffineY()));
        }
      }
      try (var update = connection.prepareStatement(
          "UPDATE enrollment SET holder_thumbprint = ? WHERE id = ?")) {
        for (int i = 0; i < ids.size(); i++) {
          update.setString(1, thumbs.get(i));
          update.setObject(2, ids.get(i));
          update.addBatch();
        }
        update.executeBatch();
      }
      alter.execute("ALTER TABLE enrollment ALTER COLUMN holder_thumbprint SET NOT NULL");
      alter.execute(
          "CREATE INDEX IF NOT EXISTS enrollment_thumbprint_idx"
              + " ON enrollment (tenant_id, holder_thumbprint)");
    }
  }
}
