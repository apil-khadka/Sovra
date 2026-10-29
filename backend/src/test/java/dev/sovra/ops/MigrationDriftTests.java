package dev.sovra.ops;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * REQUIRED_TABLES must cover every table the migrations create, so
 * readiness cannot pass with a flow table missing. If this fails
 * after adding a migration, extend the list (or justify an
 * exclusion here).
 */
class MigrationDriftTests {

  /**
   * Harness tables with no domain semantics and no app-role grant.
   * The readiness check runs as the least-privilege role, which
   * cannot see ungranted tables in information_schema — so these
   * stay out of REQUIRED_TABLES by design, not by drift.
   */
  static final Set<String> EXCLUDED = Set.of("migration_probe");

  @Test
  void requiredTablesCoverEveryMigratedTable() throws Exception {
    Path dir = Path.of("src/main/resources/db/migration");
    assertThat(dir).exists();
    Pattern create = Pattern.compile("(?i)CREATE TABLE (?:IF NOT EXISTS )?(\\w+)");
    Set<String> migrated = new HashSet<>();
    try (Stream<Path> files = Files.list(dir)) {
      for (Path file : files.filter(p -> p.toString().endsWith(".sql")).sorted().toList()) {
        Matcher matcher = create.matcher(Files.readString(file));
        while (matcher.find()) {
          migrated.add(matcher.group(1).toLowerCase());
        }
      }
    }
    migrated.removeAll(EXCLUDED);
    assertThat(migrated).isNotEmpty();
    assertThat(MigrationCheck.REQUIRED_TABLES).containsAll(migrated);
  }
}
