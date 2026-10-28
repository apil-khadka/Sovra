package dev.sovra.authz;

/** Authorization outcome with its audit-safe reason. */
public record Decision(boolean permitted, ReasonCode reasonCode, long policyVersion) {

  public static Decision permit(long policyVersion) {
    return new Decision(true, ReasonCode.PERMIT, policyVersion);
  }

  public static Decision deny(ReasonCode reasonCode, long policyVersion) {
    if (reasonCode == ReasonCode.PERMIT) {
      throw new IllegalArgumentException("deny needs a deny reason");
    }
    return new Decision(false, reasonCode, policyVersion);
  }
}
