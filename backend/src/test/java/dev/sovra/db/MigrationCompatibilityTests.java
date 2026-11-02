package dev.sovra.db;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Rolling-deploy compatibility (PROD-002): migrations are
 * expand-only, so version N+1's schema stays readable by version
 * N's code during a rolling update. Drops, renames, and type
 * rewrites deploy in a later release, only after the code stops
 * reading the old shape — never in the migration that introduces
 * the new one. If this fails, split the change across releases.
 */
class MigrationCompatibilityTests {

  static final List<Pattern> FORBIDDEN =
      List.of(
          Pattern.compile("(?i)\\bDROP\\s+TABLE\\b"),
          Pattern.compile("(?i)\\bDROP\\s+COLUMN\\b"),
          Pattern.compile("(?i)\\bALTER\\s+TABLE\\b.{0,200}?\\bRENAME\\b"),
          Pattern.compile("(?i)\\bRENAME\\s+COLUMN\\b"),
          Pattern.compile("(?i)\\bALTER\\s+COLUMN\\b.{0,200}?\\bTYPE\\b"),
          Pattern.compile("(?i)\\bTRUNCATE\\b"));

  @Test
  void migrationsAreExpandOnly() throws Exception {
    Path sqlDir = Path.of("src/main/resources/db/migration");
    Path javaDir = Path.of("src/main/java/db/migration");
    assertThat(sqlDir).exists();
    List<String> violations = new ArrayList<>();
    try (Stream<Path> files = Files.list(sqlDir)) {
      files
          .filter(p -> p.toString().endsWith(".sql"))
          .sorted()
          .forEach(p -> violations.addAll(scan(p)));
    }
    if (Files.isDirectory(javaDir)) {
      try (Stream<Path> files = Files.list(javaDir)) {
        files
            .filter(p -> p.toString().endsWith(".java"))
            .sorted()
            .forEach(p -> violations.addAll(scan(p)));
      }
    }
    assertThat(violations).as("expand-only migration violations").isEmpty();
  }

  private static List<String> scan(Path file) {
    List<String> found = new ArrayList<>();
    String content;
    try {
      content = Files.readString(file);
    } catch (Exception e) {
      throw new IllegalStateException("cannot read " + file, e);
    }
    // Comments can name a forbidden operation without performing
    // one; strip them so the scan reads statements only. Best
    // effort for -- and /* */ styles, which covers this tree.
    // REVOKE ... TRUNCATE revokes a privilege; it truncates nothing.
    String code =
        content
            .replaceAll("(?m)--[^\\n]*", "")
            .replaceAll("(?s)/\\*.*?\\*/", "")
            .replaceAll("(?i)\\bREVOKE\\b[^;]*;", "");
    for (Pattern forbidden : FORBIDDEN) {
      Matcher matcher = forbidden.matcher(code);
      while (matcher.find()) {
        int start = Math.max(0, matcher.start() - 40);
        int end = Math.min(code.length(), matcher.end() + 40);
        found.add(
            file.getFileName()
                + ": "
                + code.substring(start, end).replaceAll("\\s+", " ").trim());
      }
    }
    // Rollback safety (PROD-014): a migration-time DELETE destroys
    // rows no rollback can resurrect. DELETEs inside function
    // bodies are runtime purges, not migrate-time destruction, so
    // the scan strips $$ bodies first and bans what remains.
    String outsideFunctions = code.replaceAll("(?s)\\$\\$.*?\\$\\$", "");
    Matcher deleted =
        Pattern.compile("(?i)\\bDELETE\\s+FROM\\b").matcher(outsideFunctions);
    while (deleted.find()) {
      int start = Math.max(0, deleted.start() - 40);
      int end = Math.min(outsideFunctions.length(), deleted.end() + 40);
      found.add(
          file.getFileName()
              + " (migrate-time delete): "
              + outsideFunctions.substring(start, end).replaceAll("\\s+", " ").trim());
    }
    return found;
  }
}
