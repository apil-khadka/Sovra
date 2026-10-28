package dev.sovra.planning;

import dev.sovra.trust.TrustService;
import java.time.Instant;

/**
 * Issuer usability as the issuer and guard already define it (SOV-009,
 * SOV-014): ACTIVE standing inside the validity window. Planning tools
 * share the predicate so discovery can never surface an issuer the
 * verifier would refuse.
 */
public final class PlanningIssuers {

  private PlanningIssuers() {}

  public static boolean usable(TrustService.IssuerView issuer, Instant now) {
    return "ACTIVE".equals(issuer.status())
        && issuer.validFrom() != null
        && issuer.validThrough() != null
        && !issuer.validFrom().isAfter(now)
        && !issuer.validThrough().isBefore(now);
  }
}
