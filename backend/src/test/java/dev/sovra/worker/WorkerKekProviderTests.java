package dev.sovra.worker;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.vault.SoftwareVaultKekProvider;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Worker KEK selection (PROD-005): demo software boots, production
 * software refuses, kms without a registered provider refuses with
 * an actionable message, and unknown combinations refuse.
 */
class WorkerKekProviderTests {

  @Test
  void demoSoftwareBoots() {
    assertThat(
            WorkerKekProviders.fromEnvironment(
                Map.of("SOVRA_MODE", "demo", "SOVRA_VAULT_SEED", "dGVzdC1zZWVkLTMyLWJ5dGVzLWxvbmctZm9yLXdvcmtlciEh")))
        .isInstanceOf(SoftwareVaultKekProvider.class);
  }

  @Test
  void demoWithoutSeedRefuses() {
    assertThatThrownBy(() -> WorkerKekProviders.fromEnvironment(Map.of("SOVRA_MODE", "demo")))
        .isInstanceOf(WorkerKekProviders.WorkerBootException.class)
        .hasMessageContaining("SOVRA_VAULT_SEED is unset");
  }

  @Test
  void productionSoftwareRefuses() {
    assertThatThrownBy(
            () -> WorkerKekProviders.fromEnvironment(
                Map.of("SOVRA_MODE", "production", "SOVRA_VAULT_SEED", "dGVzdC1zZWVkLTMyLWJ5dGVzLWxvbmctZm9yLXdvcmtlciEh")))
        .isInstanceOf(WorkerKekProviders.WorkerBootException.class)
        .hasMessageContaining("requires a KMS KEK");
  }

  @Test
  void productionKmsWithoutProviderRefuses() {
    assertThatThrownBy(
            () -> WorkerKekProviders.fromEnvironment(
                Map.of("SOVRA_MODE", "production", "SOVRA_VAULT_KEK", "kms")))
        .isInstanceOf(WorkerKekProviders.WorkerBootException.class)
        .hasMessageContaining("no KMS KEK provider is registered");
  }

  @Test
  void unknownCombinationsRefuse() {
    assertThatThrownBy(
            () -> WorkerKekProviders.fromEnvironment(
                Map.of("SOVRA_MODE", "staging", "SOVRA_VAULT_KEK", "software")))
        .isInstanceOf(WorkerKekProviders.WorkerBootException.class)
        .hasMessageContaining("unsupported worker key configuration");
  }
}
