package dev.sovra.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.security.spec.ECParameterSpec;
import org.junit.jupiter.api.Test;

/**
 * Pins the single P-256 home to independently computed vectors (SECG
 * generator point, RFC 7638 canonicalization recomputed outside
 * Java/Nimbus). This is the proof the consolidation moved the code
 * without changing it: these values were produced by a separate
 * implementation, not copied from runtime output.
 */
class P256Tests {

  // SECG secp256r1 generator point.
  private static final BigInteger GX = new BigInteger(
      "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16);
  private static final BigInteger GY = new BigInteger(
      "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16);

  @Test
  void thumbprintMatchesIndependentVector() {
    assertThat(P256.base64UrlUnsigned(GX))
        .isEqualTo("axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY");
    assertThat(P256.base64UrlUnsigned(GY))
        .isEqualTo("T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU");
    assertThat(P256.thumbprint(GX, GY))
        .isEqualTo("xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M");
  }

  @Test
  void paramsAreSecp256r1() throws Exception {
    ECParameterSpec params = P256.params();
    assertThat(params.getOrder().toString(16).toUpperCase())
        .isEqualTo("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    assertThat(params.getCofactor()).isEqualTo(1);
    assertThat(params.getGenerator().getAffineX()).isEqualTo(GX);
    assertThat(params.getGenerator().getAffineY()).isEqualTo(GY);
  }

  @Test
  void fixed32PadsAndTruncates() {
    assertThat(P256.fixed32(BigInteger.ZERO)).hasSize(32);
    assertThat(P256.fixed32(BigInteger.ONE)[31]).isEqualTo((byte) 1);
    assertThat(P256.fixed32(BigInteger.ONE)[0]).isEqualTo((byte) 0);
    // 2^256 - 1 fills all 32 bytes.
    byte[] full = P256.fixed32(BigInteger.TWO.pow(256).subtract(BigInteger.ONE));
    assertThat(full).hasSize(32);
    for (byte b : full) {
      assertThat(b).isEqualTo((byte) 0xFF);
    }
  }
}
