package dev.sovra.config;

import dev.sovra.issuance.IssuerSigner;
import dev.sovra.issuance.KmsSigner;
import dev.sovra.vault.KmsVaultKekProvider;
import dev.sovra.vault.VaultKekProvider;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Production-entry gate (SOV-040). In production mode the process
 * refuses to serve when synthetic configuration or data is present:
 * the dev signer, the synthetic profile, example issuers, the
 * synthetic scope, registered synthetic keys, or the demo seed
 * tenant. It runs on every boot, so a database restored from a
 * synthetic backup is refused exactly like a misconfigured fresh
 * one. Demo mode skips the scan.
 */
@Component
public class ProductionStartupValidator implements ApplicationRunner {

  private static final Logger log = LoggerFactory.getLogger(ProductionStartupValidator.class);

  private final SovraMode mode;
  private final IssuerSigner signer;
  private final VaultKekProvider kek;
  private final JdbcTemplate global;
  private final String profile;
  private final String vaultSeed;

  public ProductionStartupValidator(
      SovraMode mode,
      IssuerSigner signer,
      VaultKekProvider kek,
      DataSource globalDataSource,
      @Value("${sovra.profile:synthetic}") String profile,
      @Value("${sovra.vault.seed:}") String vaultSeed) {
    this.mode = mode;
    this.signer = signer;
    this.kek = kek;
    this.global = new JdbcTemplate(globalDataSource);
    this.profile = profile;
    this.vaultSeed = vaultSeed;
  }

  @Override
  public void run(ApplicationArguments args) {
    if (!mode.isProduction()) {
      return;
    }
    if (!(signer instanceof KmsSigner)) {
      fail("sovra.signer must be kms in production; the synthetic dev signer cannot serve");
    }
    if (!(kek instanceof KmsVaultKekProvider)) {
      fail("sovra.vault.kek must be kms in production;"
          + " software-derived wrapping keys cannot serve");
    }
    if (vaultSeed != null && !vaultSeed.isBlank()) {
      fail("sovra.vault.seed must be empty in production;"
          + " synthetic KEK material cannot be configured");
    }
    if (!"sdjwt-vc".equals(profile)) {
      fail("sovra.profile must be sdjwt-vc in production; was: " + profile);
    }
    rejectMarkers(
        "SELECT COUNT(*) FROM issuer_record"
            + " WHERE scope = 'synthetic-only' OR issuer_id LIKE 'https://sovra.example/%'",
        "synthetic issuer rows are present");
    rejectMarkers(
        "SELECT COUNT(*) FROM issuer_signing_key WHERE issuer_id LIKE 'https://sovra.example/%'",
        "synthetic signing-key rows are present");
    rejectMarkers(
        "SELECT COUNT(*) FROM tenant WHERE slug = 'sovra-demo'", "demo seed tenant is present");
    log.info("production entry scan passed: no synthetic configuration or data detected");
  }

  private void rejectMarkers(String sql, String found) {
    Integer count = global.queryForObject(sql, Integer.class);
    if (count != null && count > 0) {
      fail(found + " (" + count + " rows); production refuses synthetic data");
    }
  }

  private static void fail(String message) {
    throw new IllegalStateException("production entry refused: " + message);
  }
}
