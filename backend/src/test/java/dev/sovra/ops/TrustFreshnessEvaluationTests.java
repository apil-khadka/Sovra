package dev.sovra.ops;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.trust.IssuerStatus;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Pure authority-freshness evaluation: stale states close readiness. */
class TrustFreshnessEvaluationTests {

  private static final Instant NOW = Instant.parse("2026-06-01T12:00:00Z");

  private static TrustFreshnessCheck.IssuerWindow window(
      IssuerStatus status, String from, String through) {
    return new TrustFreshnessCheck.IssuerWindow(
        status, Instant.parse(from), Instant.parse(through));
  }

  @Test
  void liveAuthorityIsUpWithVersionAndCount() {
    CheckResult result =
        TrustFreshnessCheck.evaluate(
            "trust_freshness",
            7,
            List.of(window(IssuerStatus.ACTIVE, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")),
            NOW,
            3);

    assertThat(result.status()).isEqualTo(CheckStatus.UP);
    assertThat(result.code()).isEqualTo("authority_live");
    assertThat(result.detail()).containsEntry("snapshotVersion", 7L);
    assertThat(result.detail()).containsEntry("usableIssuers", 1L);
  }

  @Test
  void emptySnapshotIsStaleAuthority() {
    CheckResult result =
        TrustFreshnessCheck.evaluate("trust_freshness", 7, List.of(), NOW, 3);

    assertThat(result.status()).isEqualTo(CheckStatus.DOWN);
    assertThat(result.code()).isEqualTo("stale_authority");
  }

  @Test
  void expiredIssuersAreStaleAuthority() {
    CheckResult result =
        TrustFreshnessCheck.evaluate(
            "trust_freshness",
            7,
            List.of(window(IssuerStatus.ACTIVE, "2025-01-01T00:00:00Z", "2025-12-31T00:00:00Z")),
            NOW,
            3);

    assertThat(result.status()).isEqualTo(CheckStatus.DOWN);
    assertThat(result.code()).isEqualTo("stale_authority");
    assertThat(result.detail()).containsEntry("usableIssuers", 0L);
  }

  @Test
  void revokedIssuersDoNotCountAsUsable() {
    CheckResult result =
        TrustFreshnessCheck.evaluate(
            "trust_freshness",
            7,
            List.of(window(IssuerStatus.REVOKED, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")),
            NOW,
            3);

    assertThat(result.status()).isEqualTo(CheckStatus.DOWN);
    assertThat(result.code()).isEqualTo("stale_authority");
  }

  @Test
  void oneUsableIssuerAmongExpiredKeepsAuthorityLive() {
    CheckResult result =
        TrustFreshnessCheck.evaluate(
            "trust_freshness",
            7,
            List.of(
                window(IssuerStatus.ACTIVE, "2025-01-01T00:00:00Z", "2025-12-31T00:00:00Z"),
                window(IssuerStatus.ACTIVE, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")),
            NOW,
            3);

    assertThat(result.status()).isEqualTo(CheckStatus.UP);
    assertThat(result.detail()).containsEntry("usableIssuers", 1L);
  }
}
