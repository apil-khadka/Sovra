package dev.sovra.kms;

/**
 * The key provider refused the call (PROD-005): wrong workload,
 * image, location, purpose, or key — or a revoked key, or bytes
 * that do not authenticate. Maps to an opaque 500 like
 * {@link dev.sovra.issuance.SigningRefusedException}: the caller
 * learns that the call failed, never which check fired. Outages
 * throw {@link dev.sovra.issuance.KmsUnavailableException} instead.
 */
public class KmsDeniedException extends RuntimeException {

  public KmsDeniedException(String message) {
    super(message);
  }
}
