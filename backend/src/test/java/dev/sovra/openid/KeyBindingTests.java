package dev.sovra.openid;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.crypto.impl.ECDSA;
import dev.sovra.crypto.HolderProofException;
import dev.sovra.issuance.CredentialEncoder;
import dev.sovra.issuance.IssuanceEvidence;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.issuance.IssuerSigner;
import dev.sovra.issuance.KeyRef;
import dev.sovra.issuance.SigningRefusedException;
import dev.sovra.issuance.WaltIdSdJwtVcEncoder;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

/**
 * SOV-036 KeyBinding JWT qualification: the server verifies
 * Nimbus-minted KeyBinding JWTs (independent wallet path) over
 * walt-id-issued SD-JWT VCs through the qualified walt-id
 * {@code KeyBindingJwt} interface plus Sovra header/freshness gates.
 */
class KeyBindingTests {

  private final ObjectMapper mapper = new ObjectMapper();
  private final Clock clock = Clock.fixed(Instant.parse("2026-06-01T12:00:00Z"), ZoneOffset.UTC);

  static final class TestSigner implements IssuerSigner {
    final KeyRef ref;
    final ECPrivateKey privateKey;

    TestSigner(KeyRef ref, ECPrivateKey privateKey) {
      this.ref = ref;
      this.privateKey = privateKey;
    }

    @Override
    public byte[] sign(KeyRef keyRef, byte[] payload, String aad) {
      if (!ref.equals(keyRef)) {
        throw new SigningRefusedException("unknown key");
      }
      try {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(payload);
        return ECDSA.transcodeSignatureToConcat(signature.sign(), 64);
      } catch (Exception e) {
        throw new IllegalStateException(e);
      }
    }
  }

  private record Mint(IssuanceFixtures.HolderKeys holder, String artifact) {}

  private Mint mint() throws Exception {
    IssuanceFixtures.HolderKeys issuerKeys = IssuanceFixtures.generateHolder(mapper);
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    UUID credentialId = UUID.randomUUID();
    IssuanceEvidence evidence =
        new IssuanceEvidence(
            credentialId,
            IssuanceFixtures.ISSUER_ID,
            new KeyRef(IssuanceFixtures.ISSUER_ID, "test-key", 1),
            IssuanceFixtures.ADULT_VCT,
            Map.of("adultOver18", Boolean.TRUE),
            IssuanceFixtures.thumbprint(holder),
            clock.instant(),
            clock.instant().plusSeconds(3600),
            1L,
            "/api/issuance/credentials/" + credentialId + "/status",
            holder.jwk());
    CredentialEncoder.EncodedCredential encoded =
        new WaltIdSdJwtVcEncoder(
                new TestSigner(evidence.keyRef(), issuerKeys.privateKey()))
            .encode(evidence);
    return new Mint(holder, encoded.artifact());
  }

  @Test
  void independentKeyBindingVerifies() throws Exception {
    Mint mint = mint();
    String kb =
        NimbusWallet.keyBindingAt(
            mint.holder(), "https://rp.example/cb", "test-nonce-001",
            mint.artifact(), clock.instant().getEpochSecond(), mapper);
    KeyBindingVerifier.verify(
        kb, mint.holder().publicKey(), "https://rp.example/cb", "test-nonce-001",
        mint.artifact(), clock);
  }

  @Test
  void wrongAudienceRejects() throws Exception {
    Mint mint = mint();
    String kb =
        NimbusWallet.keyBindingAt(
            mint.holder(), "https://evil.example/cb", "test-nonce-001",
            mint.artifact(), clock.instant().getEpochSecond(), mapper);
    assertThatThrownBy(
            () ->
                KeyBindingVerifier.verify(
                    kb, mint.holder().publicKey(), "https://rp.example/cb", "test-nonce-001",
                    mint.artifact(), clock))
        .isInstanceOf(HolderProofException.class);
  }

  @Test
  void wrongNonceRejects() throws Exception {
    Mint mint = mint();
    String kb =
        NimbusWallet.keyBindingAt(
            mint.holder(), "https://rp.example/cb", "other-nonce",
            mint.artifact(), clock.instant().getEpochSecond(), mapper);
    assertThatThrownBy(
            () ->
                KeyBindingVerifier.verify(
                    kb, mint.holder().publicKey(), "https://rp.example/cb", "test-nonce-001",
                    mint.artifact(), clock))
        .isInstanceOf(HolderProofException.class);
  }

  @Test
  void tamperedPresentationRejects() throws Exception {
    Mint mint = mint();
    String kb =
        NimbusWallet.keyBindingAt(
            mint.holder(), "https://rp.example/cb", "test-nonce-001",
            mint.artifact(), clock.instant().getEpochSecond(), mapper);
    int tilde = mint.artifact().indexOf('~');
    String tampered =
        mint.artifact().substring(0, tilde + 1) + "A" + mint.artifact().substring(tilde + 2);
    assertThatThrownBy(
            () ->
                KeyBindingVerifier.verify(
                    kb, mint.holder().publicKey(), "https://rp.example/cb", "test-nonce-001",
                    tampered, clock))
        .isInstanceOf(HolderProofException.class);
  }

  @Test
  void staleBindingRejects() throws Exception {
    Mint mint = mint();
    String kb =
        NimbusWallet.keyBindingAt(
            mint.holder(), "https://rp.example/cb", "test-nonce-001",
            mint.artifact(), clock.instant().minusSeconds(601).getEpochSecond(), mapper);
    assertThatThrownBy(
            () ->
                KeyBindingVerifier.verify(
                    kb, mint.holder().publicKey(), "https://rp.example/cb", "test-nonce-001",
                    mint.artifact(), clock))
        .isInstanceOf(HolderProofException.class);
  }

  @Test
  void wrongHolderKeyRejects() throws Exception {
    Mint mint = mint();
    IssuanceFixtures.HolderKeys other = IssuanceFixtures.generateHolder(mapper);
    String kb =
        NimbusWallet.keyBindingAt(
            mint.holder(), "https://rp.example/cb", "test-nonce-001",
            mint.artifact(), clock.instant().getEpochSecond(), mapper);
    assertThatThrownBy(
            () ->
                KeyBindingVerifier.verify(
                    kb, other.publicKey(), "https://rp.example/cb", "test-nonce-001",
                    mint.artifact(), clock))
        .isInstanceOf(HolderProofException.class);
  }
}
