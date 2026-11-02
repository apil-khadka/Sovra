package dev.sovra.config;

import dev.sovra.issuance.IssuerSigner;
import dev.sovra.issuance.KmsSigner;
import dev.sovra.planning.AiBudgetProperties;
import dev.sovra.planning.PlanningProperties;
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
 * Production-entry gate (SOV-040, PROD-002). In production mode the
 * process refuses to serve when synthetic configuration or data is
 * present: the dev signer, the synthetic profile, example issuers,
 * the synthetic scope, registered synthetic keys, or the demo seed
 * tenant. It also refuses an unhardened deployment posture:
 * non-HTTPS identity origins, a missing management port, or
 * in-boot migration (the migration job owns DDL; the serving
 * runtime holds no owner credential). It runs on every boot, so a
 * database restored from a synthetic backup is refused exactly like
 * a misconfigured fresh one. Demo mode skips the scan.
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
  private final boolean bffEnabled;
  private final String bffIssuer;
  private final String bffRedirectUri;
  private final String bffPostLogoutUri;
  private final int managementPort;
  private final boolean migrateOnBoot;
  private final boolean syntheticIssuers;
  private final String openidKeys;
  private final String kmsWorkload;
  private final String kmsImageDigest;
  private final String kmsLocation;
  private final AiBudgetProperties aiBudgets;
  private final PlanningProperties planning;

  public ProductionStartupValidator(
      SovraMode mode,
      IssuerSigner signer,
      VaultKekProvider kek,
      DataSource globalDataSource,
      @Value("${sovra.profile:synthetic}") String profile,
      @Value("${sovra.vault.seed:}") String vaultSeed,
      @Value("${sovra.bff.enabled:false}") boolean bffEnabled,
      @Value("${sovra.bff.issuer:}") String bffIssuer,
      @Value("${sovra.bff.redirect-uri:}") String bffRedirectUri,
      @Value("${sovra.bff.post-logout-redirect-uri:}") String bffPostLogoutUri,
      @Value("${management.server.port:-1}") int managementPort,
      @Value("${spring.flyway.enabled:true}") boolean migrateOnBoot,
      @Value("${sovra.synthetic-issuers.enabled:false}") boolean syntheticIssuers,
      @Value("${sovra.openid.keys:synthetic}") String openidKeys,
      @Value("${sovra.kms.workload:}") String kmsWorkload,
      @Value("${sovra.kms.image-digest:}") String kmsImageDigest,
      @Value("${sovra.kms.location:}") String kmsLocation,
      AiBudgetProperties aiBudgets,
      PlanningProperties planning) {
    this.mode = mode;
    this.signer = signer;
    this.kek = kek;
    this.global = new JdbcTemplate(globalDataSource);
    this.profile = profile;
    this.vaultSeed = vaultSeed;
    this.bffEnabled = bffEnabled;
    this.bffIssuer = bffIssuer;
    this.bffRedirectUri = bffRedirectUri;
    this.bffPostLogoutUri = bffPostLogoutUri;
    this.managementPort = managementPort;
    this.migrateOnBoot = migrateOnBoot;
    this.syntheticIssuers = syntheticIssuers;
    this.openidKeys = openidKeys;
    this.kmsWorkload = kmsWorkload;
    this.kmsImageDigest = kmsImageDigest;
    this.kmsLocation = kmsLocation;
    this.aiBudgets = aiBudgets;
    this.planning = planning;
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
    // The KMS beans wire without a provider so boot reaches this
    // gate; refusal stays here, explicit, instead of an autowiring
    // explosion pages away from the cause.
    if (!((KmsSigner) signer).hasProvider() || !((KmsVaultKekProvider) kek).hasProvider()) {
      fail("no KmsProvider bean is registered;"
          + " kms-mode boot refuses until the G2 provider lands");
    }
    if (vaultSeed != null && !vaultSeed.isBlank()) {
      fail("sovra.vault.seed must be empty in production;"
          + " synthetic KEK material cannot be configured");
    }
    if (!"sdjwt-vc".equals(profile)) {
      fail("sovra.profile must be sdjwt-vc in production; was: " + profile);
    }
    if (syntheticIssuers) {
      fail("sovra.synthetic-issuers.enabled must be false in production;"
          + " deterministic fixture keys cannot serve");
    }
    if (!"file".equals(openidKeys)) {
      fail("sovra.openid.keys must be file in production; was: " + openidKeys);
    }
    // The signer/KEK checks above already pinned kms mode, so every
    // production key call presents attestation — and unattested
    // configuration refuses here, before the first call.
    requireAttested("sovra.kms.workload", kmsWorkload);
    requireAttested("sovra.kms.image-digest", kmsImageDigest);
    requireAttested("sovra.kms.location", kmsLocation);
    // PROD-012: live AI in production requires a funded budget —
    // the arming flag alone must never enable metered calls.
    if (planning.liveEnabled()
        && (aiBudgets.dailyRequests() <= 0
            || aiBudgets.dailyTokens() <= 0
            || aiBudgets.maxConcurrency() <= 0)) {
      fail("live AI is armed but sovra.ai-budget is unfunded;"
          + " fund daily-requests, daily-tokens, and max-concurrency first");
    }
    if (migrateOnBoot) {
      fail("SOVRA_MIGRATE_ON_BOOT must be false in production;"
          + " the migration job owns DDL and the serving runtime holds no owner credential");
    }
    if (managementPort <= 0) {
      fail("SOVRA_MANAGEMENT_PORT must set a private scrape/health port in production");
    }
    if (bffEnabled) {
      // Absolute configured origins only: the login dance never
      // derives redirects from request headers, so spoofed
      // X-Forwarded-Host/Proto cannot hijack the flow (PROD-002
      // trusted-proxy test pins this on BffLoginTests).
      requireHttpsOrigin("sovra.bff.issuer", bffIssuer);
      requireHttpsOrigin("sovra.bff.redirect-uri", bffRedirectUri);
      requireHttpsOrigin("sovra.bff.post-logout-redirect-uri", bffPostLogoutUri);
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

  private static void requireAttested(String key, String value) {
    if (value == null || value.isBlank()) {
      fail(key + " must be configured in production;"
          + " kms-mode key calls without attestation refuse");
    }
  }

  private static void requireHttpsOrigin(String key, String value) {
    String origin = value == null ? "" : value.trim();
    if (!origin.startsWith("https://") || origin.length() <= "https://".length()) {
      fail(key + " must be an absolute https URL in production; was: " + value);
    }
    if (origin.contains(" ") || origin.contains("\t") || origin.contains("\n")) {
      fail(key + " must not contain whitespace in production; was: " + value);
    }
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
