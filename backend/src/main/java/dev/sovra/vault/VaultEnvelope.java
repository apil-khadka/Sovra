package dev.sovra.vault;

import java.nio.charset.StandardCharsets;
import java.sql.Array;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * Vault envelope AAD construction (SOV-016), shared by the service
 * and the quarantine worker so both sides authenticate identical
 * context. Content AAD binds identity plus the digest; wrap AAD
 * binds identity plus the sorted authorized purposes.
 */
public final class VaultEnvelope {

  static final String CONTENT_AAD_LABEL = "sovra-vault-content/v1";
  static final String WRAP_AAD_LABEL = "sovra-vault-wrap/v1";

  /**
   * Quarantine marker purpose (SOV-017). Objects carrying it are
   * unscanned hostile input: the content endpoint refuses them even
   * under a live grant, and only the quarantine read path opens
   * them, server-side, during promotion of a CLEAN verdict.
   */
  public static final String QUARANTINE_PURPOSE = "quarantine-scan";

  private VaultEnvelope() {}

  /** Sorted purpose names from a roles-style array column. */
  public static List<String> sortedPurposes(Array array) throws SQLException {
    if (array == null) {
      return List.of();
    }
    String[] values = (String[]) array.getArray();
    Arrays.sort(values);
    return List.of(values);
  }

  public static byte[] contentAad(
      UUID tenantId,
      String issuerId,
      UUID objectId,
      int version,
      int kekVersion,
      byte[] contentSha256) {
    return VaultCrypto.frame(CONTENT_AAD_LABEL,
        utf8(tenantId.toString()),
        utf8(issuerId),
        utf8(objectId.toString()),
        utf8(Integer.toString(version)),
        utf8(Integer.toString(kekVersion)),
        contentSha256);
  }

  public static byte[] wrapAad(
      UUID tenantId,
      String issuerId,
      UUID objectId,
      int version,
      int kekVersion,
      List<String> sortedPurposes) {
    List<byte[]> fields = new ArrayList<>();
    fields.add(utf8(tenantId.toString()));
    fields.add(utf8(issuerId));
    fields.add(utf8(objectId.toString()));
    fields.add(utf8(Integer.toString(version)));
    fields.add(utf8(Integer.toString(kekVersion)));
    for (String purpose : sortedPurposes) {
      fields.add(utf8(purpose));
    }
    return VaultCrypto.frame(WRAP_AAD_LABEL, fields.toArray(new byte[0][]));
  }

  private static byte[] utf8(String text) {
    return text.getBytes(StandardCharsets.UTF_8);
  }
}
