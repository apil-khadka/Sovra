package dev.sovra.vault;

import dev.sovra.issuance.KmsUnavailableException;
import dev.sovra.kms.KmsCallContext;
import dev.sovra.kms.KmsDeniedException;
import dev.sovra.kms.KmsProvider;
import dev.sovra.kms.KmsPurposes;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

/**
 * Production wrapping-key provider (SOV-004 section 3, SOV-038,
 * PROD-005). Delegates to the registered {@link KmsProvider} with an
 * attested call context on every wrap/unwrap. The provider stays
 * optional at wiring time so kms-mode boot reaches the startup
 * gate, which refuses clearly when no G2 provider is registered.
 * Denials surface as authentication failures (the bytes or the
 * caller are wrong); outages surface as unavailable, never as a
 * fallback value.
 */
@Service
@ConditionalOnProperty(name = "sovra.vault.kek", havingValue = "kms")
public class KmsVaultKekProvider implements VaultKekProvider {

  private final KmsProvider provider;
  private final String workload;
  private final String imageDigest;
  private final String location;

  @Autowired
  public KmsVaultKekProvider(
      ObjectProvider<KmsProvider> providers,
      @Value("${sovra.kms.workload:}") String workload,
      @Value("${sovra.kms.image-digest:}") String imageDigest,
      @Value("${sovra.kms.location:}") String location) {
    this(providers.getIfAvailable(), workload, imageDigest, location);
  }

  public KmsVaultKekProvider(
      KmsProvider provider, String workload, String imageDigest, String location) {
    this.provider = provider;
    this.workload = workload;
    this.imageDigest = imageDigest;
    this.location = location;
  }

  /** Whether a G2 provider backs this KEK. The startup gate refuses when false. */
  public boolean hasProvider() {
    return provider != null;
  }

  @Override
  public WrappedDek wrapDek(UUID tenantId, int kekVersion, byte[] dek, byte[] aad) {
    requireProvider();
    KmsProvider.KmsWrapResult result =
        provider.wrapDek(
            new KmsProvider.KmsWrapRequest(
                context(tenantId, kekVersion, aad), kekVersion, dek, aad));
    return new WrappedDek(result.wrapped(), result.nonce());
  }

  @Override
  public byte[] unwrapDek(
      UUID tenantId, int kekVersion, byte[] wrapped, byte[] nonce, byte[] aad) {
    requireProvider();
    try {
      return provider.unwrapDek(
          new KmsProvider.KmsUnwrapRequest(
              context(tenantId, kekVersion, aad), kekVersion, wrapped, nonce, aad));
    } catch (KmsDeniedException e) {
      throw new VaultAuthenticationException("kek provider denied the unwrap call");
    } catch (KmsUnavailableException e) {
      throw e;
    }
  }

  private void requireProvider() {
    if (provider == null) {
      throw new KmsUnavailableException("no kms provider is registered");
    }
  }

  private KmsCallContext context(UUID tenantId, int kekVersion, byte[] aad) {
    return new KmsCallContext(
        tenantId,
        workload,
        imageDigest,
        location,
        KmsPurposes.VAULT_DEK,
        tenantId + ":v" + kekVersion,
        new String(aad, StandardCharsets.UTF_8));
  }
}
