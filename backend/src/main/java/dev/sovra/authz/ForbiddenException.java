package dev.sovra.authz;

/** Caller is authenticated but not allowed; rendered as HTTP 403. */
public class ForbiddenException extends RuntimeException {

  private final ReasonCode reasonCode;

  public ForbiddenException(ReasonCode reasonCode) {
    super("forbidden: " + reasonCode);
    this.reasonCode = reasonCode;
  }

  public ReasonCode reasonCode() {
    return reasonCode;
  }
}
