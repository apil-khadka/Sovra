package dev.sovra.vault;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

/**
 * Synthetic wrapping-key provider (SOV-016 demo): KEKs derive per
 * tenant and version from configured seed material via HKDF-SHA256,
 * computed per call and never stored. This is a labelled fixture —
 * seed compromise exposes every version, which is exactly why
 * production refuses to boot with it (see
 * {@link dev.sovra.config.ProductionStartupValidator}) and uses the
 * G2 KMS provider instead. Requires explicit seed plus
 * non-production acknowledgement, like the synthetic signer.
 */
@Service
@ConditionalOnProperty(name = "sovra.vault.kek", havingValue = "software", matchIfMissing = true)
public class SoftwareVaultKekProvider implements VaultKekProvider {

  private static final Logger log = LoggerFactory.getLogger(SoftwareVaultKekProvider.class);

  private final byte[] seed;

  public SoftwareVaultKekProvider(
      @Value("${sovra.vault.seed:}") String seed,
      @Value("${sovra.vault.acknowledge-non-production:false}") boolean acknowledged) {
    if (seed == null || seed.isBlank() || !acknowledged) {
      throw new IllegalStateException(
          "SoftwareVaultKekProvider needs sovra.vault.seed and"
              + " sovra.vault.acknowledge-non-production=true;"
              + " production must use the KMS provider");
    }
    byte[] decoded;
    try {
      decoded = Base64.getDecoder().decode(seed.trim());
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException("sovra.vault.seed is not base64", e);
    }
    if (decoded.length < 32) {
      throw new IllegalStateException("sovra.vault.seed must decode to at least 32 bytes");
    }
    this.seed = decoded;
    log.warn("synthetic vault KEK provider active: software-derived wrapping keys are"
        + " NON-PRODUCTION doubles and must never protect real data");
  }

  @Override
  public WrappedDek wrapDek(UUID tenantId, int kekVersion, byte[] dek, byte[] aad) {
    byte[] nonce = VaultCrypto.freshNonce();
    byte[] wrapped = VaultCrypto.seal(kek(tenantId, kekVersion), nonce, dek, aad);
    return new WrappedDek(wrapped, nonce);
  }

  @Override
  public byte[] unwrapDek(
      UUID tenantId, int kekVersion, byte[] wrapped, byte[] nonce, byte[] aad) {
    return VaultCrypto.open(kek(tenantId, kekVersion), nonce, wrapped, aad);
  }

  private byte[] kek(UUID tenantId, int kekVersion) {
    return VaultCrypto.hkdfSha256(
        seed,
        ("sovra-vault-kek/v1;" + tenantId + ";v" + kekVersion).getBytes(StandardCharsets.UTF_8),
        "wrap".getBytes(StandardCharsets.UTF_8),
        32);
  }
}
