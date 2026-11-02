package dev.sovra.kms;

/**
 * The only purposes a production key may serve (PROD-005). Keys are
 * single-purpose: issuance signing keys sign issuance envelopes,
 * vault KEKs wrap data keys, and neither operation accepts the
 * other's purpose. Adding a purpose is a security review, not a
 * string edit.
 */
public final class KmsPurposes {

  /** ES256 issuance-envelope signing under an issuer key. */
  public static final String ISSUANCE_SIGNING = "issuance-signing";

  /** Vault data-encryption-key wrap/unwrap under a tenant KEK. */
  public static final String VAULT_DEK = "vault-dek";

  private KmsPurposes() {}
}
