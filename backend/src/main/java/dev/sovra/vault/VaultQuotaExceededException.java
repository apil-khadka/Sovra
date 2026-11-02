package dev.sovra.vault;

/**
 * The tenant's vault-object quota is exhausted (PROD-010). Time
 * does not help — the tenant must delete objects or receive a
 * higher quota — so this maps to a non-retryable 429, distinct
 * from rate limiting.
 */
public class VaultQuotaExceededException extends RuntimeException {

  public VaultQuotaExceededException(String message) {
    super(message);
  }
}
