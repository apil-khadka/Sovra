package dev.sovra.kms;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;

/**
 * Executable provider contract (PROD-005). The G2 provider pick
 * passes this suite against the real KMS: happy paths round-trip,
 * wrong workload/image/location/purpose/key deny, revoked keys
 * deny, tampered envelopes deny, and concurrent load stays fast.
 * To qualify a provider, subclass with its fixtures and run.
 */
public abstract class KmsProviderConformanceTests {

  /** Fresh provider per test (revocation in one test must not leak). */
  protected abstract KmsProvider provider();

  protected abstract ECPublicKey verificationKey();

  protected abstract void revokeSigningKey(String keyRef);

  protected abstract void revokeKekVersion(int kekVersion);

  protected abstract KmsCallContext context(String purpose, String keyRef);

  @Test
  void signVerifiesUnderTheProviderKey() throws Exception {
    KmsProvider provider = provider();
    byte[] payload = "issuance-envelope-fixture".getBytes();
    byte[] signature =
        provider.sign(new KmsProvider.KmsSigningRequest(signingContext(), payload));
    assertThat(signature).hasSize(64);
    Signature ecdsa = Signature.getInstance("SHA256withECDSA");
    ecdsa.initVerify(verificationKey());
    ecdsa.update(payload);
    assertThat(ecdsa.verify(TestKmsProvider.rawToDer(signature))).isTrue();
  }

  @Test
  void wrongWorkloadImageLocationPurposeDeny() {
    KmsProvider provider = provider();
    byte[] payload = "payload".getBytes();
    KmsCallContext valid = signingContext();
    assertThatThrownBy(
            () -> provider.sign(new KmsProvider.KmsSigningRequest(mutate(valid, "workload", "evil"), payload)))
        .isInstanceOf(KmsDeniedException.class);
    assertThatThrownBy(
            () -> provider.sign(new KmsProvider.KmsSigningRequest(mutate(valid, "image", "evil"), payload)))
        .isInstanceOf(KmsDeniedException.class);
    assertThatThrownBy(
            () -> provider.sign(new KmsProvider.KmsSigningRequest(mutate(valid, "location", "evil"), payload)))
        .isInstanceOf(KmsDeniedException.class);
    assertThatThrownBy(
            () ->
                provider.sign(
                    new KmsProvider.KmsSigningRequest(
                        mutate(valid, "purpose", KmsPurposes.VAULT_DEK), payload)))
        .isInstanceOf(KmsDeniedException.class);
  }

  @Test
  void unknownSigningKeyDenies() {
    KmsProvider provider = provider();
    KmsCallContext unknown = context(KmsPurposes.ISSUANCE_SIGNING, "unknown:key:v9");
    assertThatThrownBy(
            () -> provider.sign(new KmsProvider.KmsSigningRequest(unknown, "x".getBytes())))
        .isInstanceOf(KmsDeniedException.class);
  }

  @Test
  void revokedSigningKeyDenies() {
    KmsProvider provider = provider();
    revokeSigningKey(signingContext().keyRef());
    assertThatThrownBy(
            () -> provider.sign(
                new KmsProvider.KmsSigningRequest(signingContext(), "x".getBytes())))
        .isInstanceOf(KmsDeniedException.class);
  }

  @Test
  void wrapUnwrapRoundTrips() {
    KmsProvider provider = provider();
    byte[] dek = new byte[32];
    new java.security.SecureRandom().nextBytes(dek);
    byte[] aad = "envelope-aad".getBytes();
    KmsProvider.KmsWrapResult sealed =
        provider.wrapDek(new KmsProvider.KmsWrapRequest(wrapContext(), 1, dek, aad));
    assertThat(sealed.nonce()).hasSize(12);
    byte[] opened =
        provider.unwrapDek(
            new KmsProvider.KmsUnwrapRequest(
                wrapContext(), 1, sealed.wrapped(), sealed.nonce(), aad));
    assertThat(opened).isEqualTo(dek);
  }

  @Test
  void unwrapWithWrongAadDenies() {
    KmsProvider provider = provider();
    byte[] dek = new byte[32];
    KmsProvider.KmsWrapResult sealed =
        provider.wrapDek(new KmsProvider.KmsWrapRequest(wrapContext(), 1, dek, "aad-1".getBytes()));
    assertThatThrownBy(
            () -> provider.unwrapDek(
                new KmsProvider.KmsUnwrapRequest(
                    wrapContext(), 1, sealed.wrapped(), sealed.nonce(), "aad-2".getBytes())))
        .isInstanceOf(KmsDeniedException.class);
  }

  @Test
  void tamperedCiphertextDenies() {
    KmsProvider provider = provider();
    byte[] dek = new byte[32];
    byte[] aad = "aad".getBytes();
    KmsProvider.KmsWrapResult sealed =
        provider.wrapDek(new KmsProvider.KmsWrapRequest(wrapContext(), 1, dek, aad));
    byte[] tampered = sealed.wrapped().clone();
    tampered[0] ^= 0x01;
    assertThatThrownBy(
            () -> provider.unwrapDek(
                new KmsProvider.KmsUnwrapRequest(
                    wrapContext(), 1, tampered, sealed.nonce(), aad)))
        .isInstanceOf(KmsDeniedException.class);
  }

  @Test
  void wrapWithSigningPurposeDenies() {
    KmsProvider provider = provider();
    KmsCallContext crossed = context(KmsPurposes.ISSUANCE_SIGNING, "tenant:v1");
    assertThatThrownBy(
            () -> provider.wrapDek(
                new KmsProvider.KmsWrapRequest(crossed, 1, new byte[32], new byte[0])))
        .isInstanceOf(KmsDeniedException.class);
  }

  @Test
  void revokedKekVersionDenies() {
    KmsProvider provider = provider();
    revokeKekVersion(7);
    assertThatThrownBy(
            () -> provider.wrapDek(
                new KmsProvider.KmsWrapRequest(wrapContext(), 7, new byte[32], new byte[0])))
        .isInstanceOf(KmsDeniedException.class);
    assertThatThrownBy(
            () -> provider.unwrapDek(
                new KmsProvider.KmsUnwrapRequest(
                    wrapContext(), 7, new byte[48], new byte[12], new byte[0])))
        .isInstanceOf(KmsDeniedException.class);
  }

  @Test
  void concurrentLoadStaysFast() throws Exception {
    // PROD-005 quota/latency harness: the shape the G2 staging run
    // repeats against the real provider (quotas and p99 recorded,
    // not asserted, there). Here the bound only catches provider
    // serialization or deadlock.
    KmsProvider provider = provider();
    byte[] payload = "load-payload".getBytes();
    int threads = 16;
    int iterations = 25;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    try {
      List<Future<List<Long>>> futures = new ArrayList<>();
      for (int i = 0; i < threads; i++) {
        futures.add(
            pool.submit(
                () -> {
                  List<Long> latencies = new ArrayList<>();
                  for (int j = 0; j < iterations; j++) {
                    long start = System.nanoTime();
                    provider.sign(new KmsProvider.KmsSigningRequest(signingContext(), payload));
                    latencies.add((System.nanoTime() - start) / 1_000_000);
                  }
                  return latencies;
                }));
      }
      List<Long> all = new ArrayList<>();
      for (Future<List<Long>> future : futures) {
        all.addAll(future.get());
      }
      assertThat(all).hasSize(threads * iterations);
      List<Long> sorted = all.stream().sorted().toList();
      long p99 = sorted.get((int) (sorted.size() * 0.99));
      long p50 = sorted.get(sorted.size() / 2);
      System.out.println("kms conformance load: p50=" + p50 + "ms p99=" + p99 + "ms n=" + all.size());
      assertThat(p99).isLessThan(5_000);
    } finally {
      pool.shutdownNow();
    }
  }

  private KmsCallContext signingContext() {
    return context(KmsPurposes.ISSUANCE_SIGNING, TestKmsProvider.SIGNING_KEY);
  }

  private KmsCallContext wrapContext() {
    return context(KmsPurposes.VAULT_DEK, UUID.randomUUID() + ":v1");
  }

  private static KmsCallContext mutate(KmsCallContext valid, String field, String evil) {
    return new KmsCallContext(
        valid.tenantId(),
        "workload".equals(field) ? evil : valid.workload(),
        "image".equals(field) ? evil : valid.imageDigest(),
        "location".equals(field) ? evil : valid.location(),
        "purpose".equals(field) ? evil : valid.purpose(),
        valid.keyRef(),
        valid.auditAad());
  }
}
