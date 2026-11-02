package dev.sovra.kms;

/**
 * Production key provider seam (PROD-005, SOV-004 G2). The G2
 * provider pick implements this interface against the approved
 * KMS/HSM; until a bean is registered, the kms-mode signer and KEK
 * provider cannot construct and the process fails boot instead of
 * failing per request.
 *
 * <p>Contract for implementations:
 *
 * <ul>
 *   <li>Authorize {@link KmsCallContext} on EVERY call: workload,
 *       image digest, and location against attestation; purpose
 *       against the key's single authorized purpose; key reference
 *       against the live key registry (unknown or revoked refuses).
 *   <li>Throw {@link KmsDeniedException} for authorization failures
 *       (wrong caller, wrong purpose, revoked key, authentication
 *       failure). Denials map to an opaque 500: callers learn
 *       nothing about which check fired.
 *   <li>Throw {@link dev.sovra.issuance.KmsUnavailableException} for
 *       outages only (network, quota, provider error). Outages map
 *       to retryable 503, never to a fallback value.
 *   <li>Never log key material; log key references and denials.
 *   <li>Pass {@code KmsProviderConformanceTests} (test sources) —
 *       the suite is the executable acceptance contract.
 * </ul>
 */
public interface KmsProvider {

  /** Provider name for boot logs and audit (e.g. {@code cloud-kms}). */
  String name();

  /**
   * Signs the exact payload bytes with ES256 under the referenced
   * key. Returns raw JOSE R||S (64 bytes for P-256).
   */
  byte[] sign(KmsSigningRequest request);

  /** Wraps a data-encryption key under the tenant KEK version. */
  KmsWrapResult wrapDek(KmsWrapRequest request);

  /**
   * Unwraps a data-encryption key. Authentication failure is a
   * denial, not an outage.
   */
  byte[] unwrapDek(KmsUnwrapRequest request);

  /** Signing call: attested context plus the exact bytes covered. */
  record KmsSigningRequest(KmsCallContext context, byte[] payload) {}

  /**
   * Wrap call: attested context, the DEK to wrap, and the envelope
   * AAD the provider must AEAD-bind into the sealed bytes.
   */
  record KmsWrapRequest(KmsCallContext context, int kekVersion, byte[] dek, byte[] aad) {}

  /** Unwrap call: attested context, the sealed envelope, and its AAD. */
  record KmsUnwrapRequest(
      KmsCallContext context, int kekVersion, byte[] wrapped, byte[] nonce, byte[] aad) {}

  /** Wrapped DEK plus the wrap nonce. */
  record KmsWrapResult(byte[] wrapped, byte[] nonce) {}
}
