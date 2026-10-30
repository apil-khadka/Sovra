package dev.sovra.sdk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;

/** Credential lifecycle (SOV-021): create, rotate, revoke — tokens work once shown. */
class SdkAuthFlowTest extends SdkLiveBase {

  @Test
  void serviceAccountLifecycle() throws Exception {
    MachineAccount admin = mintAccount("sdk-auth-admin", "TRUST_ADMIN");
    try (SovraClient adminClient = clientFor(admin.token())) {
      AuthClient.ServiceAccountWithToken created =
          adminClient.auth.create("sdk-managed", List.of("TENANT_MEMBER"), null);
      assertThat(created.token()).startsWith("sovra_test_");
      assertThat(adminClient.auth.list().stream().map(AuthClient.ServiceAccount::id))
          .contains(created.id());
      assertThat(adminClient.auth.get(created.id()).name()).isEqualTo("sdk-managed");
      try (SovraClient managed = clientFor(created.token())) {
        assertThat(managed.ops.whoami().name()).isEqualTo("sdk-managed");
      }
      AuthClient.ServiceAccountWithToken rotated =
          adminClient.auth.rotate(created.id(), null);
      assertThat(rotated.token()).isNotEqualTo(created.token());
      try (SovraClient stale = clientFor(created.token());
          SovraClient rotatedClient = clientFor(rotated.token())) {
        assertThatThrownBy(() -> stale.ops.whoami())
            .isInstanceOf(SovraApiError.class)
            .satisfies(e -> assertThat(((SovraApiError) e).status()).isEqualTo(401));
        assertThat(rotatedClient.ops.whoami().name()).isEqualTo("sdk-managed");
      }
      AuthClient.ServiceAccount revoked = adminClient.auth.revoke(created.id());
      assertThat(revoked.revoked()).isTrue();
      try (SovraClient dead = clientFor(rotated.token())) {
        assertThatThrownBy(() -> dead.ops.whoami())
            .isInstanceOf(SovraApiError.class)
            .satisfies(e -> assertThat(((SovraApiError) e).status()).isEqualTo(401));
      }
    }
  }
}
