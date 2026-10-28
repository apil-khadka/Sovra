package dev.sovra.issuance;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

/**
 * Production signer (SOV-004 section 3). The KMS/HSM provider is selected
 * at G2 with the provider pick; until then this bean exists only to
 * reserve the binding name and fail any signing attempt loudly.
 */
@Service
@ConditionalOnProperty(name = "sovra.signer", havingValue = "kms")
public class KmsSigner implements IssuerSigner {

  @Override
  public byte[] sign(KeyRef keyRef, byte[] payload, String aad) {
    throw new KmsUnavailableException(
        "production KMS signer arrives with the G2 provider pick (SOV-004)");
  }
}
