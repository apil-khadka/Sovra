package dev.sovra.openid;

/**
 * OAuth2-style protocol error (HTTP 400 with an {@code error} code).
 * Carries only the registered code — never secrets, nonces, or
 * distinguishing detail that would oracle grant/token validity.
 */
public class OpenIdProtocolException extends RuntimeException {

  private final String error;

  public OpenIdProtocolException(String error) {
    super(error);
    this.error = error;
  }

  public String error() {
    return error;
  }
}
