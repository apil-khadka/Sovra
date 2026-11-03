package dev.sovra.kms;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.issuance.KeyRef;
import dev.sovra.issuance.KmsSigner;
import dev.sovra.issuance.KmsUnavailableException;
import dev.sovra.issuance.SigningRefusedException;
import dev.sovra.vault.KmsVaultKekProvider;
import dev.sovra.vault.VaultAuthenticationException;
import dev.sovra.vault.VaultKekProvider;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Delegation semantics (PROD-005): the kms-mode signer and KEK
 * provider build attested contexts from their configuration,
 * denials become refusal/authentication failures (opaque 500),
 * and outages pass through as unavailable (retryable 503).
 */
class KmsDelegationTests {

  static final String WORKLOAD = TestKmsProvider.WORKLOAD;
  static final String IMAGE = TestKmsProvider.IMAGE;
  static final String LOCATION = TestKmsProvider.LOCATION;

  @Test
  void signerDelegatesWithAttestedContext() {
    TestKmsProvider provider = TestKmsProvider.local();
    KmsSigner signer = new KmsSigner(provider, WORKLOAD, IMAGE, LOCATION);
    byte[] signature =
        signer.sign(
            new KeyRef("https://issuer.example/test", "test-sign", 1),
            "payload".getBytes(),
            "audit-context");
    assertThat(signature).hasSize(64);
  }

  @Test
  void signerDenialBecomesRefusal() {
    TestKmsProvider provider = TestKmsProvider.local();
    KmsSigner signer = new KmsSigner(provider, "wrong-workload", IMAGE, LOCATION);
    assertThatThrownBy(
            () -> signer.sign(
                new KeyRef("https://issuer.example/test", "test-sign", 1),
                "payload".getBytes(),
                "audit-context"))
        .isInstanceOf(SigningRefusedException.class);
  }

  @Test
  void signerOutagePassesThrough() {
    TestKmsProvider provider = TestKmsProvider.local();
    provider.outage(true);
    KmsSigner signer = new KmsSigner(provider, WORKLOAD, IMAGE, LOCATION);
    assertThatThrownBy(
            () -> signer.sign(
                new KeyRef("https://issuer.example/test", "test-sign", 1),
                "payload".getBytes(),
                "audit-context"))
        .isInstanceOf(KmsUnavailableException.class);
  }

  @Test
  void kekDelegatesAndDenialBecomesAuthenticationFailure() {
    TestKmsProvider provider = TestKmsProvider.local();
    KmsVaultKekProvider kek = new KmsVaultKekProvider(provider, WORKLOAD, IMAGE, LOCATION);
    UUID tenant = UUID.randomUUID();
    byte[] dek = new byte[32];
    new java.security.SecureRandom().nextBytes(dek);
    VaultKekProvider.WrappedDek sealed = kek.wrapDek(tenant, 1, dek, "aad".getBytes());
    assertThat(kek.unwrapDek(tenant, 1, sealed.wrapped(), sealed.nonce(), "aad".getBytes()))
        .isEqualTo(dek);
    assertThatThrownBy(
            () -> kek.unwrapDek(tenant, 1, sealed.wrapped(), sealed.nonce(), "wrong".getBytes()))
        .isInstanceOf(VaultAuthenticationException.class);
  }

  @Test
  void kekWrapDenialUsesVaultFailureTranslation() {
    TestKmsProvider provider = TestKmsProvider.local();
    provider.revokeKekVersion(1);
    KmsVaultKekProvider kek = new KmsVaultKekProvider(provider, WORKLOAD, IMAGE, LOCATION);
    assertThatThrownBy(() -> kek.wrapDek(UUID.randomUUID(), 1, new byte[32], new byte[] {1}))
        .isInstanceOf(VaultAuthenticationException.class);
  }

  @Test
  void kekOutagePassesThrough() {
    TestKmsProvider provider = TestKmsProvider.local();
    provider.outage(true);
    KmsVaultKekProvider kek = new KmsVaultKekProvider(provider, WORKLOAD, IMAGE, LOCATION);
    assertThatThrownBy(() -> kek.wrapDek(UUID.randomUUID(), 1, new byte[32], new byte[0]))
        .isInstanceOf(KmsUnavailableException.class);
  }
}
