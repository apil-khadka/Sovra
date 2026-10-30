package dev.sovra.sdk;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Vault quickstart (SOV-021): store, grant, metadata, purpose-bound read. */
class SdkVaultFlowTest extends SdkLiveBase {

  @Test
  void vaultStoreGrantReadRoundTrip() throws Exception {
    MachineAccount ops = mintAccount("sdk-vault", "ISSUER_OPS");
    MachineAccount reader = mintAccount("sdk-reader", "TENANT_MEMBER");
    byte[] content = "sdk vault bytes".getBytes(StandardCharsets.UTF_8);
    try (SovraClient opsClient = clientFor(ops.token());
        SovraClient readerClient = clientFor(reader.token())) {
      VaultClient.StoredVersion stored = opsClient.vault.store(
          "https://issuer.example/sdk-vault", "sdk object", List.of("sdk-review"), content);
      assertThat(stored.version()).isEqualTo(1);
      VaultClient.ObjectMetadata metadata = opsClient.vault.metadata(stored.objectId());
      assertThat(metadata.versions()).hasSize(1);
      String readerId = readerClient.ops.whoami().accountId();
      VaultClient.GrantView grant = opsClient.vault.grant(
          stored.objectId(), 1, "service_account", readerId, "sdk-review", "sdk-desk", 3600);
      assertThat(grant.revoked()).isFalse();
      VaultClient.ReadView read =
          readerClient.vault.read(stored.objectId(), 1, grant.grantId(), "sdk-review", "sdk-desk");
      assertThat(
          Arrays.equals(java.util.Base64.getDecoder().decode(read.contentBase64()), content))
          .isTrue();
      // Wrong purpose, same grant: the vault refuses.
      try {
        readerClient.vault.read(stored.objectId(), 1, grant.grantId(), "other-purpose",
            "sdk-desk");
        throw new AssertionError("expected the vault to refuse the wrong purpose");
      } catch (SovraApiError e) {
        assertThat(e.status()).isEqualTo(403);
      }
    }
  }
}
