package dev.sovra.issuance;

/**
 * Constrained signing boundary (SOV-004 section 3). Implementations
 * authorize the key reference on every call against the signing-key
 * registry and the active trust snapshot; unknown, revoked, or
 * out-of-epoch keys refuse. There is intentionally no raw-payload
 * endpoint: the only production caller builds payloads from validated
 * issuance evidence through the allowlisted encoder.
 */
public interface IssuerSigner {

  /**
   * Signs the payload bytes with ES256 under the referenced key.
   *
   * @param keyRef key to sign with; re-authorized on every call
   * @param payload exact bytes covered by the signature
   * @param aad canonical call context (tenant, issuer, credential, purpose,
   *     schema version); must name this call's issuer or the call refuses.
   *     Cryptographic AAD binding arrives with the G2 vault envelope; at G1
   *     the parameter is context-checked and audit-recorded.
   * @return raw JOSE R||S signature bytes (64 bytes for P-256)
   * @throws SigningRefusedException when the key is not authorized
   */
  byte[] sign(KeyRef keyRef, byte[] payload, String aad);
}
