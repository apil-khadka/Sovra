package dev.sovra.sdk;

/**
 * Typed Sovra API failure. Carries status, server code, and a
 * sanitized message — never the caller's token. Retryable marks
 * transport-level failures the caller may retry with a fresh
 * idempotency key; idempotent replays reuse the original key
 * instead (see {@link Idempotency}).
 */
public class SovraApiError extends RuntimeException {

  private final int status;
  private final String code;
  private final boolean retryable;

  public SovraApiError(int status, String code, String message, boolean retryable) {
    super(message);
    this.status = status;
    this.code = code;
    this.retryable = retryable;
  }

  public int status() {
    return status;
  }

  public String code() {
    return code;
  }

  public boolean retryable() {
    return retryable;
  }
}
