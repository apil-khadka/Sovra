package dev.sovra.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * Production deployment posture (PROD-002): the versioned production
 * compose file publishes nothing, carries no dev secrets, holds no
 * owner credential on serving runtimes, pins resource/traffic/drain
 * controls, and keeps chargeable AI off. If this fails after
 * editing deploy/production/compose.yaml, the edit weakened the
 * posture — justify it here, not by weakening the test.
 */
class ProductionComposeTests {

  static final Path PROD = Path.of("../deploy/production/compose.yaml");

  @Test
  void productionComposeIsHardened() throws Exception {
    assertThat(PROD).exists();
    String yaml = Files.readString(PROD);

    // No published ports anywhere: ingress attaches to the frontend
    // network; administration rides exec and the internal network.
    assertThat(yaml).doesNotContain("\n    ports:");

    // No demo or placeholder secrets.
    assertThat(yaml)
        .doesNotContain("sovra-dev")
        .doesNotContain("changeme")
        .doesNotContain("dev-only");

    // Production mode, KMS-backed, no synthetic profile.
    assertThat(count(yaml, "SOVRA_MODE: production")).isEqualTo(2);
    assertThat(count(yaml, "SOVRA_SIGNER: kms")).isEqualTo(2);
    assertThat(count(yaml, "SOVRA_PROFILE: sdjwt-vc")).isEqualTo(2);
    assertThat(count(yaml, "SOVRA_VAULT_KEK: kms")).isEqualTo(2);
    assertThat(yaml).doesNotContain("SOVRA_VAULT_SEED");

    // Controlled migrations: serving runtimes do not migrate and
    // hold no owner credential; only the job does.
    assertThat(count(yaml, "SOVRA_MIGRATE_ON_BOOT: \"false\"")).isEqualTo(2);
    // No owner credential *assigned* on serving runtimes (comments
    // may name it to explain its absence).
    assertThat(appBlock(yaml, "app-a")).doesNotContainPattern("SOVRA_DB_ADMIN_\\w+\\s*:");
    assertThat(appBlock(yaml, "app-b")).doesNotContainPattern("SOVRA_DB_ADMIN_\\w+\\s*:");
    assertThat(yaml).contains("dev.sovra.migrate.MigrateMain");
    assertThat(yaml).contains("service_completed_successfully");

    // Charge prevention pinned in the file: live AI off, no key.
    assertThat(count(yaml, "SOVRA_AI_LIVE_ENABLED: \"false\"")).isEqualTo(2);
    assertThat(count(yaml, "SOVRA_AI_API_KEY: \"\"")).isEqualTo(2);

    // PROD-005: attested KMS identity required on both replicas,
    // file verifier keys mounted read-only with versioned kids.
    assertThat(count(yaml, "SOVRA_KMS_WORKLOAD: ${SOVRA_KMS_WORKLOAD:?")).isEqualTo(2);
    assertThat(count(yaml, "SOVRA_KMS_IMAGE_DIGEST: ${SOVRA_KMS_IMAGE_DIGEST:?")).isEqualTo(2);
    assertThat(count(yaml, "SOVRA_KMS_LOCATION: ${SOVRA_KMS_LOCATION:?")).isEqualTo(2);
    assertThat(count(yaml, "SOVRA_OPENID_KEYS: file")).isEqualTo(2);
    assertThat(count(yaml, "/run/sovra/keys:/run/sovra/keys:ro")).isEqualTo(2);
    assertThat(count(yaml, "SOVRA_OPENID_SIGNING_KID: ${SOVRA_OPENID_SIGNING_KID:?"))
        .isEqualTo(2);
    assertThat(count(yaml, "SOVRA_OPENID_DECRYPTION_KIDS: ${SOVRA_OPENID_DECRYPTION_KIDS:?"))
        .isEqualTo(2);

    // Traffic readiness, graceful drain, bounded memory on all
    // seven services (db, keycloak-db, backup, migrate, app-a,
    // app-b, keycloak).
    assertThat(count(yaml, "/api/health/ready")).isEqualTo(2);
    assertThat(count(yaml, "SERVER_SHUTDOWN: graceful")).isEqualTo(2);
    assertThat(count(yaml, "SPRING_LIFECYCLE_TIMEOUT_PER_SHUTDOWN_PHASE: 30s")).isEqualTo(2);
    assertThat(count(yaml, "stop_grace_period:")).isEqualTo(2);
    assertThat(count(yaml, "limits:")).isEqualTo(7);

    // PROD-013: continuous WAL archiving on both primaries, a
    // dedicated backup service with its own credential, no table
    // privileges for that role (see db/init/20-backup-role.sh).
    assertThat(count(yaml, "archive_mode=on")).isEqualTo(2);
    assertThat(count(yaml, "archive_command=")).isEqualTo(2);
    assertThat(yaml).contains("backup-base.sh");
    assertThat(count(yaml, "SOVRA_BACKUP_DB_PASSWORD: ${SOVRA_BACKUP_DB_PASSWORD:?"))
        .isEqualTo(3);

    // Data plane cannot reach the internet.
    assertThat(yaml).containsPattern("(?s)sovra-back:\\s+internal: true");

    // Production Keycloak, never start-dev.
    assertThat(yaml).contains("--optimized");
    assertThat(yaml).doesNotContain("start-dev");
  }

  private static String appBlock(String yaml, String service) {
    int start = yaml.indexOf("\n  " + service + ":");
    assertThat(start).isGreaterThanOrEqualTo(0);
    Matcher next = Pattern.compile("\n  \\S").matcher(yaml);
    int end = yaml.length();
    while (next.find()) {
      if (next.start() > start) {
        end = next.start();
        break;
      }
    }
    return yaml.substring(start, end);
  }

  private static int count(String haystack, String needle) {
    int found = 0;
    int at = 0;
    while ((at = haystack.indexOf(needle, at)) >= 0) {
      found++;
      at += needle.length();
    }
    return found;
  }
}
