package dev.sovra.kms;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.issuance.KmsUnavailableException;
import java.security.interfaces.ECPublicKey;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The test provider passes the conformance suite, and its
 * outage simulation surfaces unavailable (retryable 503), never
 * denied: the suite plus this class are the bar the G2 provider
 * clears.
 */
class TestKmsProviderTests extends KmsProviderConformanceTests {

  TestKmsProvider current;

  @BeforeEach
  void fresh() {
    current = TestKmsProvider.local();
  }

  @Override
  protected KmsProvider provider() {
    return current;
  }

  @Override
  protected ECPublicKey verificationKey() {
    return current.verificationKey();
  }

  @Override
  protected void revokeSigningKey(String keyRef) {
    current.revokeKey(keyRef);
  }

  @Override
  protected void revokeKekVersion(int kekVersion) {
    current.revokeKekVersion(kekVersion);
  }

  @Override
  protected KmsCallContext context(String purpose, String keyRef) {
    return new KmsCallContext(
        UUID.randomUUID(),
        TestKmsProvider.WORKLOAD,
        TestKmsProvider.IMAGE,
        TestKmsProvider.LOCATION,
        purpose,
        keyRef,
        "conformance-fixture");
  }

  @Test
  void outageSurfacesUnavailableNeverDenied() {
    current.outage(true);
    assertThatThrownBy(
            () -> current.sign(
                new KmsProvider.KmsSigningRequest(
                    context(KmsPurposes.ISSUANCE_SIGNING, TestKmsProvider.SIGNING_KEY),
                    "x".getBytes())))
        .isInstanceOf(KmsUnavailableException.class);
    assertThat(current.name()).isEqualTo("test-kms");
    current.outage(false);
  }
}
