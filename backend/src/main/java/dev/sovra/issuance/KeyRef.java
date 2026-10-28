package dev.sovra.issuance;

/**
 * Signing-key reference (SOV-004 section 3): issuer plus key ID plus key
 * version. Possession of a reference never implies permission to sign;
 * every signer call re-authorizes it.
 */
public record KeyRef(String issuerId, String keyId, int keyVersion) {

  public KeyRef {
    if (issuerId == null || issuerId.isBlank()) {
      throw new IllegalArgumentException("issuerId is required");
    }
    if (keyId == null || keyId.isBlank() || keyId.contains(":")) {
      throw new IllegalArgumentException("keyId must be non-blank without ':'");
    }
    if (keyVersion < 1) {
      throw new IllegalArgumentException("keyVersion starts at 1");
    }
  }

  /** Stable database/text encoding: {@code issuer:keyId:vN}. */
  public String encode() {
    return issuerId + ":" + keyId + ":v" + keyVersion;
  }

  /** Splits from the right: issuer IDs are URIs and may contain ':'. */
  public static KeyRef decode(String encoded) {
    int versionAt = encoded == null ? -1 : encoded.lastIndexOf(':');
    int keyAt = versionAt < 0 ? -1 : encoded.lastIndexOf(':', versionAt - 1);
    if (keyAt < 1 || versionAt < 0 || versionAt + 1 >= encoded.length()) {
      throw new IllegalArgumentException("invalid key reference: " + encoded);
    }
    String versionText = encoded.substring(versionAt + 1);
    if (!versionText.startsWith("v")) {
      throw new IllegalArgumentException("invalid key reference: " + encoded);
    }
    try {
      return new KeyRef(
          encoded.substring(0, keyAt),
          encoded.substring(keyAt + 1, versionAt),
          Integer.parseInt(versionText.substring(1)));
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("invalid key reference: " + encoded, e);
    }
  }
}
