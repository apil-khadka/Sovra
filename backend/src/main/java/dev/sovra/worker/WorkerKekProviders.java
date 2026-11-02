package dev.sovra.worker;

import dev.sovra.vault.SoftwareVaultKekProvider;
import dev.sovra.vault.VaultKekProvider;
import java.util.Map;

/**
 * Isolated-worker KEK selection (PROD-005). The worker opens sealed
 * bytes, so its wrapping key is load-bearing: demo mode uses the
 * acknowledged software fixture, and every other combination fails
 * closed with an actionable message. Production with {@code kms}
 * fails until the G2 provider pick registers a worker KMS
 * implementation — there is deliberately no file or environment
 * fallback that could be mistaken for one.
 */
public final class WorkerKekProviders {

  private WorkerKekProviders() {}

  /**
   * Resolves the worker KEK from the environment mapping (production
   * code passes {@code System.getenv()}).
   *
   * @throws WorkerBootException when no safe provider exists; the
   *     entrypoint logs the message and exits non-zero.
   */
  public static VaultKekProvider fromEnvironment(Map<String, String> env) {
    String mode = env.getOrDefault("SOVRA_MODE", "demo");
    String kek = env.getOrDefault("SOVRA_VAULT_KEK", "software");
    if ("demo".equals(mode) && "software".equals(kek)) {
      String seed = env.getOrDefault("SOVRA_VAULT_SEED", "");
      if (seed.isBlank()) {
        throw new WorkerBootException("SOVRA_VAULT_SEED is unset");
      }
      return new SoftwareVaultKekProvider(seed, true);
    }
    if ("production".equals(mode) && "software".equals(kek)) {
      throw new WorkerBootException(
          "SOVRA_MODE=production refuses software KEK material;"
              + " production quarantine requires a KMS KEK (SOV-016 G2)");
    }
    if ("kms".equals(kek)) {
      throw new WorkerBootException(
          "no KMS KEK provider is registered for the isolated worker;"
              + " the G2 provider pick has not landed (PROD-005)");
    }
    throw new WorkerBootException(
        "unsupported worker key configuration: SOVRA_MODE=" + mode
            + " SOVRA_VAULT_KEK=" + kek);
  }

  /** Boot refusal with an operator-actionable message. */
  public static class WorkerBootException extends RuntimeException {

    WorkerBootException(String message) {
      super(message);
    }
  }
}
