package dev.sovra.guard;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Shared pure guard-context factory (SOV-014). Builds the exact
 * {@link GuardContext} the served {@code GuardService} adjudicates against —
 * issuers with standing, epochs, and per-type claim scopes from the pinned
 * snapshot, plus the frozen G1 policy documents and the versioned schema
 * evidence documents — so the evaluator, tools, and any offline scorer use
 * the SAME trusted inputs as production. No Spring, no storage, no ambient
 * time: pure function over the snapshot view.
 */
public final class GuardContexts {

  private GuardContexts() {}

  /**
   * Builds the guard context for one pinned snapshot. First row wins per
   * issuer, matching the verifier's issuer lookup; G1 snapshots carry one
   * row per issuer. The union here is a budget input only: rules v2
   * additionally requires each {@code (credentialType, claim)} pair to be
   * registry-approved FOR THAT TYPE, so union membership never authorizes
   * cross-type use.
   */
  public static GuardContext fromSnapshot(
      dev.sovra.trust.TrustService.SnapshotView snapshot) {
    Map<String, TrustedIssuer> issuers = new LinkedHashMap<>();
    for (var issuer : snapshot.issuers()) {
      List<String> claims = new ArrayList<>();
      for (String vct : issuer.credentialTypes()) {
        claims.addAll(GuardClaims.forType(vct));
      }
      issuers.putIfAbsent(
          issuer.issuerId(),
          new TrustedIssuer(
              issuer.issuerId(), issuer.credentialTypes(), List.copyOf(claims),
              List.of(issuer.keyId()), issuer.status(), issuer.validFrom(),
              issuer.validThrough()));
    }
    Map<String, PolicyDocument> policies = new LinkedHashMap<>(GuardPolicies.documents());
    policies.putAll(ApprovedSchemas.documents());
    return new GuardContext(Map.copyOf(issuers), Map.copyOf(policies));
  }
}
