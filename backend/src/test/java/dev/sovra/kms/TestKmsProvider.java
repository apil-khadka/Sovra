package dev.sovra.kms;

import dev.sovra.issuance.KmsUnavailableException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * In-memory KMS provider for tests (PROD-005). Real crypto
 * (ECDSA/AES-GCM) with strict attestation matching: the expected
 * workload, image digest, location, purpose, and key must all match
 * or the call is denied, exactly like the G2 provider must. Lives
 * in test sources — it can never serve production traffic.
 */
public final class TestKmsProvider implements KmsProvider {

  public static final String WORKLOAD = "sovra-test";
  public static final String IMAGE = "test-digest";
  public static final String LOCATION = "test-region";
  public static final String SIGNING_KEY = "https://issuer.example/test:test-sign:v1";

  private final KeyPair signingKey;
  private final Map<Integer, byte[]> kekKeys = new ConcurrentHashMap<>();
  private final Set<String> revokedKeys = ConcurrentHashMap.newKeySet();
  private final Set<Integer> revokedKekVersions = ConcurrentHashMap.newKeySet();
  private final SecureRandom random = new SecureRandom();
  private volatile boolean outage;

  private TestKmsProvider(KeyPair signingKey) {
    this.signingKey = signingKey;
  }

  /** A fresh provider with one signing key and no KEKs yet. */
  public static TestKmsProvider local() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(
          new java.security.spec.ECGenParameterSpec("secp256r1"), new SecureRandom());
      return new TestKmsProvider(generator.generateKeyPair());
    } catch (Exception e) {
      throw new IllegalStateException("test key generation failed", e);
    }
  }

  public ECPublicKey verificationKey() {
    return (ECPublicKey) signingKey.getPublic();
  }

  /** Revokes a signing key reference; further uses deny. */
  public void revokeKey(String keyRef) {
    revokedKeys.add(keyRef);
  }

  /** Revokes a KEK version; further wraps/ unwraps deny. */
  public void revokeKekVersion(int kekVersion) {
    revokedKekVersions.add(kekVersion);
  }

  /** Simulates a provider outage; calls throw unavailable, not denied. */
  public void outage(boolean outage) {
    this.outage = outage;
  }

  @Override
  public String name() {
    return "test-kms";
  }

  @Override
  public byte[] sign(KmsSigningRequest request) {
    checkOutage();
    authorize(request.context(), KmsPurposes.ISSUANCE_SIGNING);
    if (!SIGNING_KEY.equals(request.context().keyRef())
        || revokedKeys.contains(request.context().keyRef())) {
      throw new KmsDeniedException("signing key is not authorized");
    }
    try {
      Signature ecdsa = Signature.getInstance("SHA256withECDSA");
      ecdsa.initSign(signingKey.getPrivate(), random);
      ecdsa.update(request.payload());
      return derToRaw(ecdsa.sign());
    } catch (KmsDeniedException e) {
      throw e;
    } catch (Exception e) {
      throw new IllegalStateException("test signing failed", e);
    }
  }

  @Override
  public KmsWrapResult wrapDek(KmsWrapRequest request) {
    checkOutage();
    authorize(request.context(), KmsPurposes.VAULT_DEK);
    if (request.kekVersion() < 1 || revokedKekVersions.contains(request.kekVersion())) {
      throw new KmsDeniedException("kek version is not authorized");
    }
    try {
      byte[] nonce = new byte[12];
      random.nextBytes(nonce);
      Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
      gcm.init(
          Cipher.ENCRYPT_MODE,
          new SecretKeySpec(kekKey(request.kekVersion()), "AES"),
          new GCMParameterSpec(128, nonce));
      gcm.updateAAD(request.aad());
      return new KmsWrapResult(gcm.doFinal(request.dek()), nonce);
    } catch (KmsDeniedException e) {
      throw e;
    } catch (Exception e) {
      throw new IllegalStateException("test wrap failed", e);
    }
  }

  @Override
  public byte[] unwrapDek(KmsUnwrapRequest request) {
    checkOutage();
    authorize(request.context(), KmsPurposes.VAULT_DEK);
    if (request.kekVersion() < 1 || revokedKekVersions.contains(request.kekVersion())) {
      throw new KmsDeniedException("kek version is not authorized");
    }
    try {
      Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
      gcm.init(
          Cipher.DECRYPT_MODE,
          new SecretKeySpec(kekKey(request.kekVersion()), "AES"),
          new GCMParameterSpec(128, request.nonce()));
      gcm.updateAAD(request.aad());
      return gcm.doFinal(request.wrapped());
    } catch (KmsDeniedException e) {
      throw e;
    } catch (javax.crypto.AEADBadTagException e) {
      throw new KmsDeniedException("unwrap authentication failed");
    } catch (Exception e) {
      throw new IllegalStateException("test unwrap failed", e);
    }
  }

  private void authorize(KmsCallContext context, String purpose) {
    if (!WORKLOAD.equals(context.workload())
        || !IMAGE.equals(context.imageDigest())
        || !LOCATION.equals(context.location())
        || !purpose.equals(context.purpose())) {
      throw new KmsDeniedException("call context is not authorized");
    }
  }

  private void checkOutage() {
    if (outage) {
      throw new KmsUnavailableException("test outage is armed");
    }
  }

  private byte[] kekKey(int kekVersion) {
    return kekKeys.computeIfAbsent(
        kekVersion,
        version -> {
          byte[] key = new byte[32];
          random.nextBytes(key);
          return key;
        });
  }

  /** DER ECDSA signature to raw JOSE R||S (64 bytes for P-256). */
  static byte[] derToRaw(byte[] der) {
    int rLength = der[3];
    int rStart = 4;
    int sStart = rStart + rLength + 2;
    int sLength = der[sStart - 1];
    byte[] raw = new byte[64];
    copyPositive(der, rStart, rLength, raw, 0);
    copyPositive(der, sStart, sLength, raw, 32);
    return raw;
  }

  private static void copyPositive(
      byte[] der, int start, int length, byte[] raw, int offset) {
    // DER integers are signed big-endian with a possible leading
    // zero; strip it and left-pad to 32 bytes.
    int from = start;
    int count = length;
    if (count > 32) {
      from += count - 32;
      count = 32;
    }
    System.arraycopy(der, from, raw, offset + 32 - count, count);
  }

  /** Raw JOSE R||S back to DER for JCA verification. */
  public static byte[] rawToDer(byte[] raw) {
    byte[] r = trimLeadingZeros(raw, 0);
    byte[] s = trimLeadingZeros(raw, 32);
    int total = 2 + r.length + 2 + s.length;
    byte[] der = new byte[2 + total];
    der[0] = 0x30;
    der[1] = (byte) total;
    der[2] = 0x02;
    der[3] = (byte) r.length;
    System.arraycopy(r, 0, der, 4, r.length);
    der[4 + r.length] = 0x02;
    der[5 + r.length] = (byte) s.length;
    System.arraycopy(s, 0, der, 6 + r.length, s.length);
    return der;
  }

  private static byte[] trimLeadingZeros(byte[] raw, int offset) {
    int start = offset;
    while (start < offset + 31 && raw[start] == 0) {
      start++;
    }
    int length = offset + 32 - start;
    boolean pad = (raw[start] & 0x80) != 0;
    byte[] out = new byte[length + (pad ? 1 : 0)];
    System.arraycopy(raw, start, out, pad ? 1 : 0, length);
    return out;
  }

}
