package dev.sovra.issuance;

import dev.sovra.kms.KmsCallContext;
import dev.sovra.kms.KmsProvider;
import dev.sovra.kms.KmsPurposes;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

/**
 * Production signer (SOV-004 section 3, PROD-005). Delegates to the
 * registered {@link KmsProvider} with an attested call context
 * (workload, image digest, location) on every signing call. The
 * provider stays optional at wiring time so kms-mode boot reaches
 * the startup gate, which refuses clearly when no G2 provider is
 * registered; calls without a provider fail unavailable, never
 * silently.
 */
@Service
@ConditionalOnProperty(name = "sovra.signer", havingValue = "kms")
public class KmsSigner implements IssuerSigner {

  private final KmsProvider provider;
  private final String workload;
  private final String imageDigest;
  private final String location;

  @Autowired
  public KmsSigner(
      ObjectProvider<KmsProvider> providers,
      @Value("${sovra.kms.workload:}") String workload,
      @Value("${sovra.kms.image-digest:}") String imageDigest,
      @Value("${sovra.kms.location:}") String location) {
    this(providers.getIfAvailable(), workload, imageDigest, location);
  }

  public KmsSigner(
      KmsProvider provider, String workload, String imageDigest, String location) {
    this.provider = provider;
    this.workload = workload;
    this.imageDigest = imageDigest;
    this.location = location;
  }

  /** Whether a G2 provider backs this signer. The startup gate refuses when false. */
  public boolean hasProvider() {
    return provider != null;
  }

  @Override
  public byte[] sign(KeyRef keyRef, byte[] payload, String aad) {
    if (provider == null) {
      throw new KmsUnavailableException("no kms provider is registered");
    }
    // Issuer signing keys are platform-scoped (the trust snapshot
    // authorizes them, not a tenant pin), so the context carries no
    // tenant; the provider still binds workload, image, location,
    // purpose, and key reference before it signs.
    KmsCallContext context =
        new KmsCallContext(
            null, workload, imageDigest, location,
            KmsPurposes.ISSUANCE_SIGNING, keyRef.encode(), aad);
    try {
      return provider.sign(new KmsProvider.KmsSigningRequest(context, payload));
    } catch (dev.sovra.kms.KmsDeniedException e) {
      throw new SigningRefusedException("kms provider denied the signing call");
    }
  }
}
