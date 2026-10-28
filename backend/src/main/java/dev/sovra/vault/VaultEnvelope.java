package dev.sovra.vault;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
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

  private VaultEnvelope() {}

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
