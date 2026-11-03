package dev.sovra.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class VaultCryptoTests {

  private static final HexFormat HEX = HexFormat.of();

  @Test
  void hkdfSha256MatchesRfc5869TestCaseOne() {
    byte[] ikm = HEX.parseHex("0b".repeat(22));
    byte[] salt = HEX.parseHex("000102030405060708090a0b0c");
    byte[] info = HEX.parseHex("f0f1f2f3f4f5f6f7f8f9");

    assertThat(HEX.formatHex(VaultCrypto.hkdfSha256(ikm, salt, info, 42)))
        .isEqualTo("3cb25f25faacd57a90434f64d0362f2a"
            + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            + "34007208d5b887185865");
  }

  @Test
  void hkdfSha256UsesZeroSaltWhenSaltIsOmittedOrEmpty() {
    byte[] ikm = HEX.parseHex("0b".repeat(22));
    String expected = "8da4e775a563c18f715f802a063c5a31"
        + "b8a11f5c5ee1879ec3454e5f3c738d2d"
        + "9d201395faa4b61a96c8";

    assertThat(HEX.formatHex(VaultCrypto.hkdfSha256(ikm, null, null, 42)))
        .isEqualTo(expected);
    assertThat(HEX.formatHex(VaultCrypto.hkdfSha256(ikm, new byte[0], new byte[0], 42)))
        .isEqualTo(expected);
  }

  @Test
  void hkdfSha256RejectsLengthsOutsideRfc5869Range() {
    assertThat(VaultCrypto.hkdfSha256(new byte[] {1}, null, null, 0)).isEmpty();
    assertThat(VaultCrypto.hkdfSha256(new byte[] {1}, null, null, 8160)).hasSize(8160);
    assertThatThrownBy(() -> VaultCrypto.hkdfSha256(new byte[] {1}, null, null, -1))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> VaultCrypto.hkdfSha256(new byte[] {1}, null, null, 8161))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void aesGcmReleasesPlaintextOnlyForMatchingTagAndAad() {
    byte[] key = new byte[VaultCrypto.DEK_BYTES];
    byte[] nonce = VaultCrypto.freshNonce();
    byte[] aad = "tenant/object/version".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    byte[] plaintext = "encrypted document bytes".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    byte[] ciphertext = VaultCrypto.seal(key, nonce, plaintext, aad);

    assertThat(VaultCrypto.open(key, nonce, ciphertext, aad)).containsExactly(plaintext);
    byte[] modified = ciphertext.clone();
    modified[0] ^= 1;
    assertThatThrownBy(() -> VaultCrypto.open(key, nonce, modified, aad))
        .isInstanceOf(VaultAuthenticationException.class);
    assertThatThrownBy(() -> VaultCrypto.open(key, nonce, ciphertext, new byte[] {1}))
        .isInstanceOf(VaultAuthenticationException.class);
  }
}
