package dev.sovra.sdk;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Live-stack contract tests (SOV-021): every test talks to a real
 * backend over HTTP. The stack must be up
 * ({@code docker compose up --build -d}); machine accounts mint
 * through the compose database exactly like the browser suite.
 */
abstract class SdkLiveBase {

  static final String BASE =
      System.getenv().getOrDefault("SOVRA_SDK_BASE", "http://localhost:8080");
  static final String DB_CONTAINER =
      System.getenv().getOrDefault("SOVRA_E2E_DB_CONTAINER", "sovra-db-1");
  static final String DB_PASSWORD =
      System.getenv().getOrDefault("SOVRA_DB_ADMIN_PASSWORD", "sovra-dev-only");

  static final String ISSUER_ID = "https://sovra.example/issuers/synth-1";
  static final String ADULT_VCT = "https://sovra.example/vct/adult-status/1";

  record MachineAccount(String tenantId, String token) {}

  static String psql(String sql) throws Exception {
    Process process = new ProcessBuilder(
        "docker", "exec", "-e", "PGPASSWORD=" + DB_PASSWORD, DB_CONTAINER,
        "psql", "-U", "sovra", "-d", "sovra", "-v", "ON_ERROR_STOP=1", "-tA", "-c", sql)
        .redirectErrorStream(true)
        .start();
    String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    int status = process.waitFor();
    if (status != 0) {
      throw new IllegalStateException("psql failed: " + output.trim());
    }
    return output.trim().split("\n")[0].trim();
  }

  static MachineAccount mintAccount(String name, String roles) throws Exception {
    String tenantId = psql("SELECT id FROM tenant WHERE slug = 'sovra-demo';");
    if (tenantId.isEmpty()) {
      throw new IllegalStateException("sovra-demo tenant missing (is the compose stack up?)");
    }
    byte[] random = new byte[32];
    new SecureRandom().nextBytes(random);
    String token = "sovra_test_" + Base64.getUrlEncoder().withoutPadding().encodeToString(random);
    String prefix = token.substring("sovra_test_".length(), "sovra_test_".length() + 8);
    String digest = HexFormat.of().formatHex(
        MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
    psql("INSERT INTO service_account (tenant_id, name, token_prefix, token_hash, roles) VALUES ('"
        + tenantId + "', '" + name + "', '" + prefix + "', decode('" + digest + "', 'hex'), '{"
        + roles + "}');");
    return new MachineAccount(tenantId, token);
  }

  static SovraClient clientFor(String token) {
    return new SovraClient(BASE, token);
  }
}
