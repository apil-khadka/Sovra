package dev.sovra.guard;

import dev.sovra.issuance.SyntheticJwtEncoder;
import java.util.List;

/**
 * Per-type attestable-claim allowlists (SOV-001 section 2). G1 trusts
 * exactly one type with exactly one claim; unknown types attest nothing,
 * so unfamiliar schemas fail closed without code changes.
 */
public final class GuardClaims {

  private GuardClaims() {}

  public static List<String> forType(String vct) {
    if (SyntheticJwtEncoder.ADULT_VCT.equals(vct)) {
      return List.of("adultOver18");
    }
    return List.of();
  }
}
