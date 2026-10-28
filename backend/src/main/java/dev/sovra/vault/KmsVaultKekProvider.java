package dev.sovra.vault;

import dev.sovra.issuance.KmsUnavailableException;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

/**
 * Production wrapping-key provider (SOV-004 section 3, SOV-038). The
 * KMS/HSM pick lands at G2; until then this bean exists only to
 * reserve the binding name and fail every wrap/unwrap loudly with
 * the same outage the live provider would surface.
 */
@Service
@ConditionalOnProperty(name = "sovra.vault.kek", havingValue = "kms")
public class KmsVaultKekProvider implements VaultKekProvider {

  @Override
  public WrappedDek wrapDek(UUID tenantId, int kekVersion, byte[] dek, byte[] aad) {
    throw new KmsUnavailableException(
        "production vault KMS arrives with the G2 provider pick (SOV-004, SOV-038)");
  }

  @Override
  public byte[] unwrapDek(
      UUID tenantId, int kekVersion, byte[] wrapped, byte[] nonce, byte[] aad) {
    throw new KmsUnavailableException(
        "production vault KMS arrives with the G2 provider pick (SOV-004, SOV-038)");
  }
}
