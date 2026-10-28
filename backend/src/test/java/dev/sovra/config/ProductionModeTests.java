package dev.sovra.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import dev.sovra.issuance.IssuerSigner;
import dev.sovra.issuance.KmsSigner;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

/**
 * Production-entry rules without Spring (SOV-040): mode parsing and
 * the validator's demo bypass. Database-backed cases live in
 * ProductionValidatorTests; full-boot refusal in ProductionBootTests.
 */
class ProductionModeTests {

  @Test
  void modeParsing() {
    assertThat(new SovraMode("demo").isProduction()).isFalse();
    assertThat(new SovraMode("production").isProduction()).isTrue();
    assertThatThrownBy(() -> new SovraMode("prod"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("demo or production");
    assertThatThrownBy(() -> new SovraMode(""))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void demoSkipsTheEntryScan() {
    IssuerSigner devDouble = (ref, payload, aad) -> new byte[64];
    ProductionStartupValidator validator = new ProductionStartupValidator(
        new SovraMode("demo"), devDouble, mock(DataSource.class), "synthetic");
    validator.run(null);
  }

  @Test
  void productionRefusesTheDevSigner() {
    IssuerSigner devDouble = (ref, payload, aad) -> new byte[64];
    ProductionStartupValidator validator = new ProductionStartupValidator(
        new SovraMode("production"), devDouble, mock(DataSource.class), "sdjwt-vc");
    assertThatThrownBy(() -> validator.run(null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("signer must be kms");
  }

  @Test
  void productionRefusesTheSyntheticProfile() {
    ProductionStartupValidator validator = new ProductionStartupValidator(
        new SovraMode("production"), new KmsSigner(), mock(DataSource.class), "synthetic");
    assertThatThrownBy(() -> validator.run(null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("profile must be sdjwt-vc");
  }
}
